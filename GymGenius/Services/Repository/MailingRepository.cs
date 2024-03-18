using GymGenius.Services.Interface;
using Microsoft.Extensions.Options;
using MimeKit;
using MailKit.Net.Smtp;
using GymGenius.Models.Email;

namespace GymGenius.Services.Repository
{
    public class MailingRepository : IMailingRepository
    {
        private readonly MailSetting _setting;

        public MailingRepository(IOptions<MailSetting> setting)
        {
            _setting = setting.Value;
        }

        public async Task SendingMail(string mailTo, string subject, string body, IList<IFormFile> attechments = null)
        {
            var email = new MimeMessage()
            {
                Sender = MailboxAddress.Parse(_setting.Email),
                Subject = subject,
            };

            email.To.Add(MailboxAddress.Parse(mailTo));

            //Body

            var builder = new BodyBuilder();

            if (attechments != null)
            {
                byte[] fileBytes;
                foreach (var file in attechments)
                {
                    if (file.Length > 0)
                    {
                        using var ms = new MemoryStream();
                        file.CopyTo(ms);

                        fileBytes = ms.ToArray();
                        builder.Attachments.Add(file.FileName, fileBytes, ContentType.Parse(file.ContentType));
                    }
                }
            }

            builder.HtmlBody = body;

            email.Body = builder.ToMessageBody();

            email.From.Add(new MailboxAddress(_setting.DisplayName, _setting.Email));

            using var smtp = new SmtpClient();

            smtp.Connect(_setting.Host, _setting.Port, MailKit.Security.SecureSocketOptions.StartTls);

            smtp.Authenticate(_setting.Email, _setting.Password);

            await smtp.SendAsync(email);

            smtp.Disconnect(true);
        }
    }
}
