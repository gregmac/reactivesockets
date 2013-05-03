using System;
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
        private SslStream _stream;
        private readonly object _getStreamLock = new object();
        
        private readonly string _targetHost;
        private readonly bool _leaveInnerStreamOpen;
        private readonly RemoteCertificateValidationCallback _userCertificateValidationCallback;
        private readonly LocalCertificateSelectionCallback _userCertificateSelectionCallback;
        private readonly EncryptionPolicy _encryptionPolicy;
        private readonly X509CertificateCollection _clientCertificates;
        private readonly SslProtocols _enabledSslProtocols;
        private readonly bool _checkCertificateRevocation;
        
        
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
            _targetHost = targetHost;
            _leaveInnerStreamOpen = leaveInnerStreamOpen;
            _userCertificateValidationCallback = userCertificateValidationCallback;
            _userCertificateSelectionCallback = userCertificateSelectionCallback;
            _encryptionPolicy = encryptionPolicy;
            _clientCertificates = clientCertificates;
            _enabledSslProtocols = enabledSslProtocols;
            _checkCertificateRevocation = checkCertificateRevocation;
        }

        /// <summary>
        /// Returns an SSL-wrapped stream. This method always returns the same stream
        /// object, initialzed when this is first called. This method is thread-safe.
        /// </summary>
        /// <returns></returns>
        protected override System.IO.Stream GetStream()
        {
            lock (_getStreamLock)
            {
                if (_stream == null)
                {
                    _stream = new SslStream(
                        base.GetStream(),
                        leaveInnerStreamOpen: _leaveInnerStreamOpen,
                        userCertificateValidationCallback: _userCertificateValidationCallback,
                        userCertificateSelectionCallback: _userCertificateSelectionCallback,
                        encryptionPolicy: _encryptionPolicy);

                    _stream.AuthenticateAsClient(
                        _targetHost,
                        _clientCertificates ?? new X509CertificateCollection(),
                        _enabledSslProtocols,
                        _checkCertificateRevocation);
                }
                return _stream;
            }
        }
    }
}
