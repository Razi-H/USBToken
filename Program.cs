using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Logging;
using Net.Pkcs11Interop.Tests;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;

using BCX509 = Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.Cms;
using Pkcs7SignatureGenerator;
using Org.BouncyCastle.Security;

namespace pkcs11int
{
    public class Program
    {
        public static void Main(string[] args)
        {
            showCerts();
            return;
            _02_FindAllObjectsTest();
            return;
            string pkcs11LibraryPath = @"/usr/local/lib/libshuttle_p11v220.dylib";

            // Create factories used by Pkcs11Interop library
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            // Load unmanaged PKCS#11 library
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Show general information about loaded library
                ILibraryInfo libraryInfo = pkcs11Library.GetInfo();

                Console.WriteLine("Library");
                Console.WriteLine("  Manufacturer:       " + libraryInfo.ManufacturerId);
                Console.WriteLine("  Description:        " + libraryInfo.LibraryDescription);
                Console.WriteLine("  Version:            " + libraryInfo.LibraryVersion);

                // Get list of all available slots
                foreach (ISlot slot in pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    // Show basic information about slot
                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    Console.WriteLine();
                    Console.WriteLine("Slot");
                    Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
                    Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
                    Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        // Show basic information about token present in the slot
                        ITokenInfo tokenInfo = slot.GetTokenInfo();

                        Console.WriteLine("Token");
                        Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                        Console.WriteLine("  Model:              " + tokenInfo.Model);
                        Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                        Console.WriteLine("  Label:              " + tokenInfo.Label);

                        // Show list of mechanisms (algorithms) supported by the token
                        Console.WriteLine("Supported mechanisms: ");
                        foreach (CKM mechanism in slot.GetMechanismList())
                            Console.WriteLine("  " + mechanism);
                    }
                }

                //CreateHostBuilder(args).Build().Run();
            }
        }

        public static void _01_BasicLoggingTest()
        {
            // Specify path to the log file
            //string logFilePath = Path.Combine(Path.GetTempPath(), @"Pkcs11Interop.log");
            string logFilePath = @"Pkcs11Interop.log";

            //DeleteFile(logFilePath);

            // Setup logger factory implementation
            var loggerFactory = new SimplePkcs11InteropLoggerFactory();
            loggerFactory.MinLogLevel = Pkcs11InteropLogLevel.Trace;
            loggerFactory.DisableConsoleOutput();
            loggerFactory.DisableDiagnosticsTraceOutput();
            loggerFactory.EnableFileOutput(logFilePath);

            // Set logger factory implementation that will be used by Pkcs11Interop library
            Pkcs11InteropLoggerFactory.SetLoggerFactory(loggerFactory);

            string pkcs11LibraryPath = @"/usr/local/lib/libshuttle_p11v220.dylib";

            // Create factories used by Pkcs11Interop library
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            // Use Pkcs11Interop library as usual
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                ILibraryInfo libraryInfo = pkcs11Library.GetInfo();
            }

            //DeleteFile(logFilePath);
        }

        private static void DeleteFile(string path)
        {
            if (File.Exists(path))
                File.Delete(path);
        }

        public static string ExportToPEM(System.Security.Cryptography.X509Certificates.X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }
        public static void showCerts()
        {

// var signatute = File.ReadAllBytes("sign.p7s");

//                         //System.Security.Cryptography

//                         System.Security.Cryptography.Pkcs.SignedCms cms = new System.Security.Cryptography.Pkcs.SignedCms(new System.Security.Cryptography.Pkcs.ContentInfo(Encoding.UTF8.GetBytes("Salams")), detached: true);
//                         cms.Decode(signatute);
//                         // This next line throws a CryptographicException if the signature can't be verified
//                         cms.CheckSignature(true);

//                         System.Security.Cryptography.Pkcs.SignerInfoCollection signers = cms.SignerInfos;

//                         if (signers.Count == 1)
//                         {
//                             var iss = signers[0].Certificate.Subject;
//                             // probably fail
//                         }

//                         return;

            X509CertificateParser _x509CertificateParser = new X509CertificateParser();

            using (IPkcs11Library pkcs11Library = Settings.Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                ISlot slot = Helpers.GetUsableSlot(pkcs11Library);
                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
                    //objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, UTF8Encoding.UTF8.GetBytes("Certificat d'Authentification CPS")));
                    //CurrentSession.FindObjectsInit(objectAttributes);
                    var oObjCollection = session.FindAllObjects(objectAttributes);
                    //if (oObjCollection.Count > 0)
                    foreach (var item6 in oObjCollection)
                    {
                        var item2 = oObjCollection[0];
                        var item = oObjCollection[1];
                        var oAttriVal = session.GetAttributeValue(item, new List<CKA>() { CKA.CKA_VALUE, CKA.CKA_ID }).FirstOrDefault();
                        var oResult = oAttriVal.GetValueAsByteArray();

                        X509Certificate bcCert = _x509CertificateParser.ReadCertificate(oResult);

  var oAttriVal2 = session.GetAttributeValue(item2, new List<CKA>() { CKA.CKA_VALUE, CKA.CKA_ID }).FirstOrDefault();
                        var oResult2 = oAttriVal2.GetValueAsByteArray();

                        X509Certificate bcCert2 = _x509CertificateParser.ReadCertificate(oResult2);


                        var res = bcCert.CertificateStructure.Subject;

                        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate(bcCert.GetEncoded());
                        var signatute = GenerateSignature(Encoding.UTF8.GetBytes("Salam"), false, bcCert2, new List<X509Certificate>{bcCert,bcCert2});

                        File.WriteAllText("file.txt", "Salam");
                        File.WriteAllBytes("sign3.p7s", signatute);

                        //SignedCms
                        //var signatute = File.ReadAllBytes("sign.p7s");

                        //System.Security.Cryptography

                        System.Security.Cryptography.Pkcs.SignedCms cms = new System.Security.Cryptography.Pkcs.SignedCms(new System.Security.Cryptography.Pkcs.ContentInfo(Encoding.UTF8.GetBytes("Salam")), detached: false);
                        cms.Decode(signatute);
                        // This next line throws a CryptographicException if the signature can't be verified
                        cms.CheckSignature(true);

                        System.Security.Cryptography.Pkcs.SignerInfoCollection signers = cms.SignerInfos;

                        if (signers.Count != 1)
                        {
                            //signers[0].Certificate.IssuerName
                            // probably fail
                        }
                        return;
                        //File.WriteAllText("1.cer", ExportToPEM(cert));


                        // oResult = new X509Certificate2(oAttriVal.GetValueAsByteArray());
                        // X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                        // store.Open(OpenFlags.ReadWrite);
                        // store.Add(oResult);
                        // store.Close();
                    }
                    session.Logout();
                }
            }
        }

        private static ICkRsaPkcsPssParams CreateCkRsaPkcsPssParams(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    return Settings.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA_1,
                        mgf: (ulong)CKG.CKG_MGF1_SHA1,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                case HashAlgorithm.SHA256:
                    return Settings.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA256,
                        mgf: (ulong)CKG.CKG_MGF1_SHA256,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                case HashAlgorithm.SHA384:
                    return Settings.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA384,
                        mgf: (ulong)CKG.CKG_MGF1_SHA384,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                case HashAlgorithm.SHA512:
                    return Settings.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA512,
                        mgf: (ulong)CKG.CKG_MGF1_SHA512,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                default:
                    throw new NotSupportedException("Unsupported hash algorithm");
            }
        }

        private static byte[] ComputeDigest(IDigest digest, byte[] data)
        {
            if (digest == null)
                throw new ArgumentNullException("digest");

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] hash = new byte[digest.GetDigestSize()];

            digest.Reset();
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;
        }

        private static byte[] CreateDigestInfo(byte[] hash, string hashOid)
        {
            DigestInfo digestInfo = new DigestInfo(
                algID: new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(hashOid),
                    parameters: DerNull.Instance
                ),
                digest: hash
            );

            return digestInfo.GetDerEncoded();
        }

        private static HashAlgorithm _hashAlgorihtm = HashAlgorithm.SHA1;
        private static SignatureScheme _signatureScheme = SignatureScheme.RSASSA_PKCS1_v1_5;
        public static byte[] GenerateSignature(byte[] data, bool detached, BCX509.X509Certificate signingCertificate, ICollection<BCX509.X509Certificate> certPath)
        {

            IPkcs11Library pkcs11Library = Settings.Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType);

            // Find first slot with token present
            ISlot _slot = Helpers.GetUsableSlot(pkcs11Library);



            string hashOid = HashAlgorithmUtils.GetHashOid(_hashAlgorihtm);
            IDigest hashGenerator = HashAlgorithmUtils.GetHashGenerator(_hashAlgorihtm);

            // Compute hash of input data
            byte[] dataHash = ComputeDigest(hashGenerator, data);

            // Construct SignerInfo.signedAttrs
            Asn1EncodableVector signedAttributesVector = new Asn1EncodableVector();

            // Add PKCS#9 contentType signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    attrType: new DerObjectIdentifier(OID.PKCS9AtContentType),
                    attrValues: new DerSet(new DerObjectIdentifier(OID.PKCS7IdData))));

            // Add PKCS#9 messageDigest signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    attrType: new DerObjectIdentifier(OID.PKCS9AtMessageDigest),
                    attrValues: new DerSet(new DerOctetString(dataHash))));

            // Add PKCS#9 signingTime signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    attrType: new DerObjectIdentifier(OID.PKCS9AtSigningTime),
                    attrValues: new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(new DerUtcTime(DateTime.UtcNow)))));

            // Compute digest of SignerInfo.signedAttrs
            DerSet signedAttributes = new DerSet(signedAttributesVector);
            byte[] signedAttributesDigest = ComputeDigest(hashGenerator, signedAttributes.GetDerEncoded());

            // Sign digest of SignerInfo.signedAttrs with private key stored on PKCS#11 compatible device
            Asn1OctetString digestSignature = null;
            AlgorithmIdentifier digestSignatureAlgorithm = null;
            IObjectHandle _privateKeyHandle;

            if (_signatureScheme == SignatureScheme.RSASSA_PKCS1_v1_5)
            {
                // Construct DigestInfo
                byte[] digestInfo = CreateDigestInfo(signedAttributesDigest, hashOid);

                // Sign DigestInfo with CKM_RSA_PKCS mechanism
                byte[] signature = null;

                //new Pkcs11InteropFactories().MechanismFactory

                using (ISession session = _slot.OpenSession(SessionType.ReadOnly))
                using (IMechanism mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS))
                {
                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));

                    // Find all objects that match provided attributes
                    List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);

                    _privateKeyHandle = foundObjects[0];

                    signature = session.Sign(mechanism, _privateKeyHandle, digestInfo);
                }
                // Construct SignerInfo.signature
                digestSignature = new DerOctetString(signature);

                // Construct SignerInfo.signatureAlgorithm
                digestSignatureAlgorithm = new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(OID.PKCS1RsaEncryption),
                    parameters: DerNull.Instance
                );
            }
            else if (_signatureScheme == SignatureScheme.RSASSA_PSS)
            {
                //var pssMechanismParams = Settings.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(_hashAlgorihtm);
                // Construct parameters for CKM_RSA_PKCS_PSS mechanism
                var pssMechanismParams = CreateCkRsaPkcsPssParams(_hashAlgorihtm);

                // Sign digest with CKM_RSA_PKCS_PSS mechanism
                byte[] signature = null;


                using (ISession session = _slot.OpenSession(SessionType.ReadOnly))
                using (IMechanism mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_PSS, pssMechanismParams))
                {
                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));

                    // Find all objects that match provided attributes
                    List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);

                    _privateKeyHandle = foundObjects[0];
                    signature = session.Sign(mechanism, _privateKeyHandle, signedAttributesDigest);
                }

                // Construct SignerInfo.signature
                digestSignature = new DerOctetString(signature);

                // Construct SignerInfo.signatureAlgorithm
                digestSignatureAlgorithm = new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(OID.PKCS1RsassaPss),
                    parameters: new Org.BouncyCastle.Asn1.Pkcs.RsassaPssParameters(
                        hashAlgorithm: new AlgorithmIdentifier(
                            algorithm: new DerObjectIdentifier(hashOid),
                            parameters: DerNull.Instance
                        ),
                        maskGenAlgorithm: new AlgorithmIdentifier(
                            algorithm: new DerObjectIdentifier(OID.PKCS1Mgf1),
                            parameters: new AlgorithmIdentifier(
                                algorithm: new DerObjectIdentifier(hashOid),
                                parameters: DerNull.Instance
                            )
                        ),
                        saltLength: new DerInteger(hashGenerator.GetDigestSize()),
                        trailerField: new DerInteger(1)
                    )
                );
            }
            else
            {
                throw new NotSupportedException("Unsupported signature scheme");
            }

            // Construct SignerInfo
            SignerInfo signerInfo = new SignerInfo(
                sid: new SignerIdentifier(new IssuerAndSerialNumber(signingCertificate.IssuerDN, signingCertificate.SerialNumber)),
                digAlgorithm: new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(hashOid),
                    parameters: DerNull.Instance
                ),
                authenticatedAttributes: signedAttributes,
                digEncryptionAlgorithm: digestSignatureAlgorithm,
                encryptedDigest: digestSignature,
                unauthenticatedAttributes: null
            );

            // Construct SignedData.digestAlgorithms
            Asn1EncodableVector digestAlgorithmsVector = new Asn1EncodableVector();
            digestAlgorithmsVector.Add(
                new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(hashOid),
                    parameters: DerNull.Instance));

            // Construct SignedData.encapContentInfo
            ContentInfo encapContentInfo = new ContentInfo(
                contentType: new DerObjectIdentifier(OID.PKCS7IdData),
                content: (detached) ? null : new DerOctetString(data));

            // Construct SignedData.certificates
            Asn1EncodableVector certificatesVector = new Asn1EncodableVector();
            foreach (BCX509.X509Certificate cert in certPath)
                certificatesVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetEncoded())));

            // Construct SignedData.signerInfos
            Asn1EncodableVector signerInfosVector = new Asn1EncodableVector();
            signerInfosVector.Add(signerInfo.ToAsn1Object());



            // Construct SignedData
            SignedData signedData = new SignedData(
                digestAlgorithms: new DerSet(digestAlgorithmsVector),
                contentInfo: encapContentInfo,
                certificates: new BerSet(certificatesVector),
                crls: null,
                signerInfos: new DerSet(signerInfosVector));

            // Construct top level ContentInfo
            ContentInfo contentInfo = new ContentInfo(
                contentType: new DerObjectIdentifier(OID.PKCS7IdSignedData),
                content: signedData);

            var signer = SignerUtilities.GetSigner("SHA1withRSA");
            //var signer = SignerUtilities.GetSigner(new DerObjectIdentifier(OID.PKCS7IdSignedData));
            signer.Init(false, signingCertificate.GetPublicKey());
            signer.BlockUpdate(data, 0, data.Length);

            var er = signer.VerifySignature(contentInfo.GetDerEncoded());

            return contentInfo.GetDerEncoded();
        }

        public static void _02_FindAllObjectsTest()
        {
            using (IPkcs11Library pkcs11Library = Settings.Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                ISlot slot = Helpers.GetUsableSlot(pkcs11Library);
                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Let's create two objects so we can find something
                    //IObjectHandle objectHandle1 = Helpers.CreateDataObject(session);
                    //IObjectHandle objectHandle2 = Helpers.CreateDataObject(session);

                    // Prepare attribute template that defines search criteria
                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                    List<IObjectAttribute> objectAttributes22 = new List<IObjectAttribute>();
                    objectAttributes22.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                    //objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                    //objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                    //objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));

                    // Find all objects that match provided attributes
                    List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);
                    List<IObjectHandle> foundObjects2 = session.FindAllObjects(objectAttributes22);


                    byte[] iv = session.GenerateRandom(8);
                    // Specify encryption mechanism with initialization vector as parameter
                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);

                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Our new password");
                    // Encrypt data
                    byte[] encryptedData = session.Encrypt(mechanism, foundObjects[0], sourceData);
                    byte[] decryotedData = session.Decrypt(mechanism, foundObjects2[0], encryptedData);
                    // Do something interesting with found objects


                    string str = ConvertUtils.BytesToUtf8String(decryotedData);
                    List<CKA> attributes = new List<CKA>();
                    attributes.Add(CKA.CKA_OBJECT_ID);
                    attributes.Add(CKA.CKA_SUBJECT);
                    attributes.Add(CKA.CKA_PUBLIC_KEY_INFO);
                    attributes.Add(CKA.CKA_KEY_TYPE);
                    //CKA.CKA_ISSUER

                    //attributes.Add(CKA.CKA_VALUE);
                    // Get value of specified attributes
                    List<IObjectAttribute> objectAttributes2 = session.GetAttributeValue(foundObjects[0], attributes);
                    //objectAttributes2[0].getVa
                    //session.DestroyObject(objectHandle2);
                    //session.DestroyObject(objectHandle1);
                    session.Logout();
                }
            }
        }
        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
