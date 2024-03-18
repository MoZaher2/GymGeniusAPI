namespace GymGenius.Services.Interface
{
    public interface IMailingRepository
    {
        Task SendingMail(string mailTo, string subject, string body, IList<IFormFile> attechments = null);
    }
}
