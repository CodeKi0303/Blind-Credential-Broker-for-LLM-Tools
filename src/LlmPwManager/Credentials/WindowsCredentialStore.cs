using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace LlmPwManager.Credentials;

internal sealed class WindowsCredentialStore(string targetPrefix) : ICredentialStore
{
    private const int CRED_TYPE_GENERIC = 1;
    private const int CRED_PERSIST_LOCAL_MACHINE = 2;

    public bool Exists(string alias)
    {
        if (!CredRead(Target(alias), CRED_TYPE_GENERIC, 0, out var credentialPtr))
        {
            return false;
        }

        CredFree(credentialPtr);
        return true;
    }

    public string? GetSecret(string alias)
    {
        if (!CredRead(Target(alias), CRED_TYPE_GENERIC, 0, out var credentialPtr))
        {
            return null;
        }

        try
        {
            var credential = Marshal.PtrToStructure<CREDENTIAL>(credentialPtr);
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
            {
                return "";
            }

            var bytes = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);
            return Encoding.Unicode.GetString(bytes);
        }
        finally
        {
            CredFree(credentialPtr);
        }
    }

    public void SaveSecret(string alias, string secret)
    {
        var secretBytes = Encoding.Unicode.GetBytes(secret);
        var blob = Marshal.AllocCoTaskMem(secretBytes.Length);

        try
        {
            Marshal.Copy(secretBytes, 0, blob, secretBytes.Length);
            var credential = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = Target(alias),
                CredentialBlobSize = secretBytes.Length,
                CredentialBlob = blob,
                Persist = CRED_PERSIST_LOCAL_MACHINE,
                UserName = Environment.UserName
            };

            if (!CredWrite(ref credential, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            CryptographicErase(secretBytes);
            CryptographicErase(blob, secretBytes.Length);
            Marshal.FreeCoTaskMem(blob);
        }
    }

    public void DeleteSecret(string alias)
    {
        CredDelete(Target(alias), CRED_TYPE_GENERIC, 0);
    }

    private string Target(string alias) => $"{targetPrefix}:{alias}";

    private static void CryptographicErase(byte[] bytes)
    {
        Array.Clear(bytes);
    }

    private static void CryptographicErase(IntPtr buffer, int length)
    {
        if (buffer == IntPtr.Zero || length <= 0)
        {
            return;
        }

        var zeros = new byte[length];
        Marshal.Copy(zeros, 0, buffer, length);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref CREDENTIAL userCredential, int flags);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, int type, int flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string? Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }
}
