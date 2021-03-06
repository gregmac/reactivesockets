﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ReactiveSockets
{
    /// <summary>
    /// An SSL-wrapped <see cref="ReactiveClient"/>.
    /// </summary>
    public class ReactiveSslClient : ReactiveClient
    {
        private SslStream stream;
        private readonly object getStreamLock = new object();
        
        private readonly string targetHost;
        private readonly bool leaveInnerStreamOpen;
        private readonly RemoteCertificateValidationCallback userCertificateValidationCallback;
        private readonly LocalCertificateSelectionCallback userCertificateSelectionCallback;
        private readonly EncryptionPolicy encryptionPolicy;
        private readonly X509CertificateCollection clientCertificates;
        private readonly SslProtocols enabledSslProtocols;
        private readonly bool checkCertificateRevocation;
        
        
        /// <summary>
        /// Initializes the reactive client.
        /// </summary>
        /// <param name="hostname">The host name or IP address of the TCP server to connect to.</param>
        /// <param name="port">The port to connect to.</param>
        /// <param name="targetHost">The name of the server that will share this <see cref="T:System.Net.Security.SslStream"/>. 
        /// (From <see cref="SslStream.AuthenticateAsClient(string,System.Security.Cryptography.X509Certificates.X509CertificateCollection,System.Security.Authentication.SslProtocols,bool)"/>)</param>
        /// <param name="leaveInnerStreamOpen">A Boolean value that indicates the closure behavior of the <see cref="T:System.IO.Stream"/> 
        /// object used by the <see cref="T:System.Net.Security.SslStream"/> for sending and receiving data. This parameter indicates if the 
        /// inner stream is left open. (From <see cref="T:System.Net.Security.SslStream"/> constructor)</param>
        /// <param name="userCertificateValidationCallback">A <see cref="T:System.Net.Security.RemoteCertificateValidationCallback"/> 
        /// delegate responsible for validating the certificate supplied by the remote party. (From <see cref="T:System.Net.Security.SslStream"/> constructor)</param>
        /// <param name="userCertificateSelectionCallback">A <see cref="T:System.Net.Security.LocalCertificateSelectionCallback"/> delegate 
        /// responsible for selecting the certificate used for authentication. (From <see cref="T:System.Net.Security.SslStream"/> constructor)</param>
        /// <param name="encryptionPolicy">The <see cref="T:System.Net.Security.EncryptionPolicy"/> to use. (From <see cref="T:System.Net.Security.SslStream"/> constructor)</param>
        /// <param name="clientCertificates">The <see cref="T:System.Security.Cryptography.X509Certificates.X509CertificateCollection"/> that contains client certificates.
        /// (From <see cref="SslStream.AuthenticateAsClient(string,System.Security.Cryptography.X509Certificates.X509CertificateCollection,System.Security.Authentication.SslProtocols,bool)"/>)</param>
        /// <param name="enabledSslProtocols">The <see cref="T:System.Security.Authentication.SslProtocols"/> value that represents the protocol used for authentication.
        /// (From <see cref="SslStream.AuthenticateAsClient(string,System.Security.Cryptography.X509Certificates.X509CertificateCollection,System.Security.Authentication.SslProtocols,bool)"/>)</param>
        /// <param name="checkCertificateRevocation">A <see cref="T:System.Boolean"/> value that specifies whether the certificate revocation list is checked during authentication.
        /// (From <see cref="SslStream.AuthenticateAsClient(string,System.Security.Cryptography.X509Certificates.X509CertificateCollection,System.Security.Authentication.SslProtocols,bool)"/>)</param>
        public ReactiveSslClient(
            string hostname, 
            int port, 
            string targetHost,
            bool leaveInnerStreamOpen = false,
            RemoteCertificateValidationCallback userCertificateValidationCallback = null,
            LocalCertificateSelectionCallback userCertificateSelectionCallback = null,
            EncryptionPolicy encryptionPolicy = EncryptionPolicy.RequireEncryption,
            X509CertificateCollection clientCertificates = null,
            SslProtocols enabledSslProtocols = SslProtocols.Ssl3 | SslProtocols.Tls,
            bool checkCertificateRevocation = false) 
            : base(hostname, port)
        {
            this.targetHost = targetHost;
            this.leaveInnerStreamOpen = leaveInnerStreamOpen;
            this.userCertificateValidationCallback = userCertificateValidationCallback;
            this.userCertificateSelectionCallback = userCertificateSelectionCallback;
            this.encryptionPolicy = encryptionPolicy;
            this.clientCertificates = clientCertificates;
            this.enabledSslProtocols = enabledSslProtocols;
            this.checkCertificateRevocation = checkCertificateRevocation;
        }

        /// <summary>
        /// Returns an SSL-wrapped stream. This method always returns the same stream
        /// object, initialzed when this is first called. This method is thread-safe.
        /// </summary>
        /// <returns></returns>
        protected override System.IO.Stream GetStream()
        {
            lock (getStreamLock)
            {
                if (stream == null)
                {
                    stream = new SslStream(
                        base.GetStream(),
                        leaveInnerStreamOpen: leaveInnerStreamOpen,
                        userCertificateValidationCallback: userCertificateValidationCallback,
                        userCertificateSelectionCallback: userCertificateSelectionCallback,
                        encryptionPolicy: encryptionPolicy);

                    stream.AuthenticateAsClient(
                        targetHost,
                        clientCertificates ?? new X509CertificateCollection(),
                        enabledSslProtocols,
                        checkCertificateRevocation);
                }
                return stream;
            }
        }
    }
}
