using System.Drawing;
using System.Windows.Forms;

namespace LlmPwManager.Ui;

internal sealed class WindowsCredentialPrompt : ICredentialPrompt
{
    public string? RequestPassword(string alias, string label, string userName, string reason)
    {
        string? result = null;
        var thread = new Thread(() =>
        {
            Application.EnableVisualStyles();
            using var form = new Form
            {
                Text = "LLM Password Manager",
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen,
                MinimizeBox = false,
                MaximizeBox = false,
                Width = 440,
                Height = 245,
                TopMost = true
            };

            var title = new Label
            {
                Text = string.IsNullOrWhiteSpace(label) ? alias : label,
                Left = 20,
                Top = 18,
                Width = 380,
                Height = 24,
                Font = new Font(SystemFonts.MessageBoxFont ?? SystemFonts.DefaultFont, FontStyle.Bold)
            };
            var details = new Label
            {
                Text = $"{reason}\r\nAlias: {alias}\r\nUser: {userName}",
                Left = 20,
                Top = 50,
                Width = 380,
                Height = 62
            };
            var input = new TextBox
            {
                Left = 20,
                Top = 125,
                Width = 380,
                UseSystemPasswordChar = true
            };
            var ok = new Button
            {
                Text = "Test and Save",
                Left = 190,
                Top = 160,
                Width = 100,
                DialogResult = DialogResult.OK
            };
            var cancel = new Button
            {
                Text = "Cancel",
                Left = 300,
                Top = 160,
                Width = 100,
                DialogResult = DialogResult.Cancel
            };

            form.Controls.AddRange([title, details, input, ok, cancel]);
            form.AcceptButton = ok;
            form.CancelButton = cancel;

            if (form.ShowDialog() == DialogResult.OK)
            {
                result = input.Text;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return result;
    }
}
