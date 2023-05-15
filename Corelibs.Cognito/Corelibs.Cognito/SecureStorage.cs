using System.Security.Cryptography;
using System.Text;

namespace Corelibs.Cognito;

public class SecureStorage : ISecureStorage
{
    private readonly byte[] entropy = new byte[] { 1, 2, 3, 4, 5 }; // Change this to a unique byte array.
    private readonly string _appName;

    public SecureStorage(string appName)
    {
        _appName = appName;
    }

    public async Task SetAsync(string key, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        byte[] encryptedData = ProtectedData.Protect(bytes, entropy, DataProtectionScope.CurrentUser);
        string path = GetStoragePath(key);
        await File.WriteAllBytesAsync(path, encryptedData);
    }

    public async Task<string> GetAsync(string key)
    {
        string path = GetStoragePath(key);
        if (!File.Exists(path))
        {
            return null;
        }
        byte[] encryptedData = await File.ReadAllBytesAsync(path);
        byte[] data = ProtectedData.Unprotect(encryptedData, entropy, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(data);
    }

    public bool Remove(string key)
    {
        string path = GetStoragePath(key);
        if (!File.Exists(path))
            return false;
     
        File.Delete(path);

        return true;
    }

    public void RemoveAll()
    {
        string folderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), _appName);
        if (Directory.Exists(folderPath))
        {
            var files = Directory.EnumerateFiles(folderPath);
            foreach (var file in files)
            {
                File.Delete(file);
            }
        }
    }

    private string GetStoragePath(string key)
    {
        string folderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), _appName);
        if (!Directory.Exists(folderPath))
        {
            Directory.CreateDirectory(folderPath);
        }

        string filePath = Path.Combine(folderPath, $"{key}.bin");
        return filePath;
    }
}
