using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PoC
{
    class poc
    {
        static void Main(string[] args)
        {
            //var ecdsa = ECDsa.Create(); // generate asymmetric key pair
            //var req = new CertificateRequest("cn=foobar", ecdsa, HashAlgorithmName.SHA256);
            //var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));

            //// Create PFX (PKCS #12) with private key
            //File.WriteAllBytes("c:\\temp\\mycert.pfx", cert.Export(X509ContentType.Pfx, "P@55w0rd"));

            //// Create Base 64 encoded CER (public key only)
            //File.WriteAllText("c:\\temp\\mycert.cer",
            //    "-----BEGIN CERTIFICATE-----\r\n"
            //    + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
            //    + "\r\n-----END CERTIFICATE-----");

            X509Store store = new X509Store(StoreLocation.LocalMachine);
            store.Open(OpenFlags.MaxAllowed);
            X509Certificate2Collection cers = store.Certificates.Find(X509FindType.FindBySubjectName, "test.millercom.net", false);
            X509Certificate2 cer;
            RsaPrivateCrtKeyParameters r;
            if (cers.Count > 0)
            {
                cer = cers[0];

                //var parser = new X509CertificateParser();
                //var bouncyCertificate = parser.ReadCertificate(cer.RawData);

                //var privateKey = DotNetUtilities.GetKeyPair(cer.PrivateKey).Private;
                

                //string privateKey = akp.();

                RSACryptoServiceProvider rsa = cer.PrivateKey as RSACryptoServiceProvider;
                RSAParameters rSAParameters = rsa.ExportParameters(true);

                byte[] privateCertRawBytes = new byte[rSAParameters.Modulus.Length + 
                                                      rSAParameters.Exponent.Length + 
                                                      rSAParameters.D.Length + 
                                                      rSAParameters.P.Length +
                                                      rSAParameters.Q.Length +
                                                      rSAParameters.DP.Length +
                                                      rSAParameters.DQ.Length +
                                                      rSAParameters.InverseQ.Length
                                                      ];

                int index = 0;
                rSAParameters.Modulus.CopyTo(privateCertRawBytes, index);
                index += rSAParameters.Modulus.Length;
                
                rSAParameters.Exponent.CopyTo(privateCertRawBytes, index);
                index += rSAParameters.Exponent.Length;
                
                rSAParameters.D.CopyTo(privateCertRawBytes, index);
                index += rSAParameters.D.Length;

                rSAParameters.P.CopyTo(privateCertRawBytes, index);
                index += rSAParameters.P.Length;

                rSAParameters.Q.CopyTo(privateCertRawBytes, index);
                index += rSAParameters.Q.Length;

                rSAParameters.DP.CopyTo(privateCertRawBytes, index);
                index += rSAParameters.DP.Length;

                rSAParameters.DQ.CopyTo(privateCertRawBytes, index);
                index += rSAParameters.DQ.Length;

                rSAParameters.InverseQ.CopyTo(privateCertRawBytes, index);

                string privateCert = Convert.ToBase64String(privateCertRawBytes);

                //r = new RsaPrivateCrtKeyParameters(
                //        new BigInteger(1, rSAParameters.Modulus),
                //        new BigInteger(1, rSAParameters.Exponent),
                //        new BigInteger(1, rSAParameters.D),
                //        new BigInteger(1, rSAParameters.P),
                //        new BigInteger(1, rSAParameters.Q),
                //        new BigInteger(1, rSAParameters.DP),
                //        new BigInteger(1, rSAParameters.DQ),
                //        new BigInteger(1, rSAParameters.InverseQ)
                //    );

            };





            //X509Certificate2 pfx = new X509Certificate2(@"c:\temp\cert.pfx", "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            //RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)pfx.PrivateKey;

            //AsymmetricCipherKeyPair keypair = DotNetUtilities.GetRsaKeyPair(rsa);
            //RSA rsaPriv = DotNetUtilities.ToRSA(keypair.Private as RsaPrivateCrtKeyParameters);

            //MemoryStream ms = new MemoryStream();
            //TextWriter tw = new StreamWriter(ms);
            //PemWriter pw = new PemWriter(tw);

            //pw.WriteObject(keypair.Private);

            //string privkey = Encoding.ASCII.GetString(ms.GetBuffer());
            //byte[] privateBytes = Encoding.ASCII.GetBytes(privkey);
            //byte[] privateB2 = ms.GetBuffer();

            //bool identical = true;
            //for (int i = 0; i < privateBytes.Length; i++)
            //{
            //    byte b1 = privateBytes[i];
            //    byte b2 = privateB2[i];
            //    if (b1 != b2)
            //        identical = false;
            //}

            //tw.Flush();
            //tw.Dispose();


        }


    }
}
