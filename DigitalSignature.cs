/******************************************/
/******************************************/
/*****************Bu DLL'i*****************/
/**************S.Ahmet TAÇGIN**************/
/**************kodlanmıştır...*************/
/******************************************/
/******************************************/
using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Collections;


namespace DigitalSignatureClass
{  
    
    /// <summary>
    /// Dosyalara dijital imza atar.
    /// </summary>
    public class DigitalSignature
    {
        public static RSACryptoServiceProvider RSAalg;
        byte[] publicKey;

        FileStream fist;
        BinaryWriter biwr;
        BinaryReader bire;
        RSAParameters keyPrivate, keyPublic;

        /// <summary>
        /// Dosyalara dijital imza atar.
        /// </summary>
        public DigitalSignature()
        {
            RSAalg = new RSACryptoServiceProvider();
            keyPrivate = RSAalg.ExportParameters(true);
            keyPublic = RSAalg.ExportParameters(false);
            publicKey = Encoding.ASCII.GetBytes(RSAalg.ToXmlString(false));
        }
        /// <summary>
        /// İmzalanacak dosyayı verdiğinizde dosya ile aynı path' e .sign uzantılı imzayı ekler.
        /// </summary>
        /// <param name="filePath">İmzalamak istenilen dosyanın path'i</param>
        /// <returns>true metotun imzayı başarılı bir şekilde oluşturduğunu false ise bir hata ile karşılaşıldığında geri döner.</returns>
        public bool SignFile(string filePath)
        {
            try
            {
                string directoryName = Path.GetDirectoryName(filePath);
                string fileName = Path.GetFileNameWithoutExtension(filePath);

                byte[] byteArrayOfOriginalData = originalData(filePath);//imzalı resmi çekicez
                byte[] signedData = SignBytes(byteArrayOfOriginalData, keyPrivate);

                fist = new FileStream(directoryName + "\\" + fileName + ".sign", FileMode.Create, FileAccess.Write);
                biwr = new BinaryWriter(fist);

                biwr.Write(publicKey);
                biwr.Write(signedData);

                biwr.Close();
                fist.Close();

                return true;

            }
            catch
            {
                return false;
            }
        }
         /// <summary>
        ///  Onaylanacak dosyanın path'inı ve imzanin path'ini alır.
        /// </summary>
        /// <param name="filePath">Onaylamak istenilen dosyanın path'i</param>
        /// <param name="signPath">İmzanın (.sign uzantılı) path'i</param>
        /// <returns>0 metotun dosyayı onayladığı, 1 dosya onaylanmadığı, -1 ise bir hata ile karşılaşıldığında geri döner.</returns>

        public int VerifySignedFile(string filePath, string signPath)
        {
            try
            {

                byte[] signatureAndPublicKey = signatureWithPublicKey(signPath);
                byte[] signatureArray = new byte[128];
                for (int i = 0; i < signatureAndPublicKey.Length; i++)
                {
                    if (i < 243)
                        publicKey[i] = signatureAndPublicKey[i];

                    if (i >= 243)
                        signatureArray[i - 243] = signatureAndPublicKey[i];
                }

                RSAalg.FromXmlString(ASCIIEncoding.ASCII.GetString(publicKey));
                keyPublic = RSAalg.ExportParameters((false));

                if (VerifySigned(originalData(filePath), signatureArray, keyPublic))
                {
                    return 0;
                }
                else
                {
                    return 1;
                }
            }
            catch
            {
                return -1;
            }
        }

        //datayı byte arraye çevirir..
        private byte[] originalData(string m_filePath)
        {
            try
            {
                fist = new FileStream(m_filePath, FileMode.Open);
                bire = new BinaryReader(fist);

                byte[] fileByteArray = bire.ReadBytes(Convert.ToInt32(fist.Length));

                bire.Close();
                fist.Close();

                return fileByteArray;

            }
            catch
            {
                return null;
            }
        }

        private byte[] signatureWithPublicKey(string m_signPath)
        {
            try
            {
                fist = new FileStream(m_signPath, FileMode.Open);
                bire = new BinaryReader(fist);

                byte[] fileByteArray = bire.ReadBytes(Convert.ToInt32(fist.Length));

                bire.Close();
                fist.Close();

                return fileByteArray;

            }
            catch
            {

                return null;
            }
        }


        //byte dizisini imzalar ve geriye bir imza döndürür byte dizisi olarak
        private static byte[] SignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                RSAalg.ImportParameters(Key);
                return RSAalg.SignData(DataToSign, "SHA512");//geri dönüş değeri imza
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        //dosyayı doğrulama yapar
        private static bool VerifySigned(byte[] originalData, byte[] signature, RSAParameters Key)
        {
            try
            {
                RSAalg.ImportParameters(Key);
                return RSAalg.VerifyData(originalData, "SHA512", signature);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

    }
}
