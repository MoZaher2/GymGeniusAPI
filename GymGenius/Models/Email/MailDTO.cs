namespace GymGenius.Models.Email
{
    public class MailDTO
    {
        public string ToEmail { get; set; }

        public string Subject { get; set; }

        public string Body { get; set; }

        public IList<IFormFile>? attechments {  get; set; }
    }
}
