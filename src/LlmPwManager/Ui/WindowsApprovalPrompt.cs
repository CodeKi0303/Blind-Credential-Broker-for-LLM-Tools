using System.Drawing;
using System.Windows.Forms;

namespace LlmPwManager.Ui;

internal sealed class WindowsApprovalPrompt : IApprovalPrompt
{
    public bool Approve(string title, string target, string action, string reason)
    {
        var approved = false;
        var thread = new Thread(() =>
        {
            Application.EnableVisualStyles();
            using var form = new Form
            {
                Text = "LLM Password Manager Approval",
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen,
                MinimizeBox = false,
                MaximizeBox = false,
                Width = 520,
                Height = 310,
                TopMost = true
            };

            var header = new Label
            {
                Text = title,
                Left = 20,
                Top = 18,
                Width = 460,
                Height = 24,
                Font = new Font(SystemFonts.MessageBoxFont ?? SystemFonts.DefaultFont, FontStyle.Bold)
            };
            var body = new TextBox
            {
                Left = 20,
                Top = 52,
                Width = 460,
                Height = 160,
                Multiline = true,
                ReadOnly = true,
                BorderStyle = BorderStyle.FixedSingle,
                Text = $"Target: {target}\r\nReason: {reason}\r\n\r\nAction:\r\n{action}"
            };
            var approve = new Button
            {
                Text = "Approve",
                Left = 270,
                Top = 225,
                Width = 100,
                DialogResult = DialogResult.OK
            };
            var deny = new Button
            {
                Text = "Deny",
                Left = 380,
                Top = 225,
                Width = 100,
                DialogResult = DialogResult.Cancel
            };

            form.Controls.AddRange([header, body, approve, deny]);
            form.AcceptButton = approve;
            form.CancelButton = deny;
            approved = form.ShowDialog() == DialogResult.OK;
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return approved;
    }
}
