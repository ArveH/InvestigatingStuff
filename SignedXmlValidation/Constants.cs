namespace TestSignedXml
{
    public static class Constants
    {
        public static class ConfigKeys
        {
            public static string AppInsights = "ApplicationInsights:InstrumentationKey";
            public static string LogFilePath = "Serilog:LogFileFullPath";
            public static string CertFileName = "Crypto:CertFileName";
            public static string CertPassword = "Crypto:CertPassword";
        }

        public static string DefaultLogFilePath = @"D:\home\LogFiles\Application\fakeidp.log";
        public static int IdentityTokenLifeTime = 3600;

        public static class AccessTokenType
        {
            public const string Jwt = "JWT";
        }

        public static class AuthorizeRequest
        {
            public const string Scope = "scope";
            public const string ResponseType = "response_type";
            public const string ClientId = "client_id";
            public const string RedirectUri = "redirect_uri";
            public const string State = "state";
            public const string ResponseMode = "response_mode";
            public const string Nonce = "nonce";
            public const string LoginHint = "login_hint";
        }

        public static class EndSessionRequest
        {
            public const string IdTokenHint = "id_token_hint";
            public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
            public const string State = "state";
            public const string Sid = "sid";
            public const string Issuer = "iss";
        }

        public static class AuthorizeResponse
        {
            public const string Scope = "scope";
            public const string Code = "code";
            public const string AccessToken = "access_token";
            public const string ExpiresIn = "expires_in";
            public const string TokenType = "token_type";
            public const string RefreshToken = "refresh_token";
            public const string IdentityToken = "id_token";
            public const string State = "state";
        }

        public class Oidc
        {
            public const string Prefix = "/oidc";

            public static class EndpointName
            {
                public const string Authorize = "Authorize";
                public const string Token = "Token";
                public const string DeviceAuthorization = "DeviceAuthorization";
                public const string Discovery = "Discovery";
                public const string DiscoveryKey = "DiscoveryKey";
                public const string Introspection = "Introspection";
                public const string Revocation = "Revocation";
                public const string EndSession = "Endsession";
                public const string CheckSession = "Checksession";
                public const string UserInfo = "Userinfo";
            }

            public static class RoutePath
            {
                public const string ConnectPathPrefix = "/connect";

                public const string Authorize = Oidc.Prefix + ConnectPathPrefix + "/authorize";
                public const string AuthorizeCallback = Oidc.Prefix + Authorize + "/callback";
                public const string DiscoveryConfiguration = Oidc.Prefix + "/.well-known/openid-configuration";
                public const string DiscoveryWebKeys = DiscoveryConfiguration + "/jwks";
                public const string Token = Oidc.Prefix + ConnectPathPrefix + "/token";
                public const string Revocation = Oidc.Prefix + ConnectPathPrefix + "/revocation";
                public const string UserInfo = Oidc.Prefix + ConnectPathPrefix + "/userinfo";
                public const string Introspection = Oidc.Prefix + ConnectPathPrefix + "/introspect";
                public const string EndSession = Oidc.Prefix + ConnectPathPrefix + "/endsession";
                public const string EndSessionCallback = Oidc.Prefix + EndSession + "/callback";
                public const string CheckSession = Oidc.Prefix + ConnectPathPrefix + "/checksession";
                public const string DeviceAuthorization = Oidc.Prefix + ConnectPathPrefix + "/deviceauthorization";
            }
        }

        public const string EntityId = "EntityId";
        public const string Metadata = "Metadata";

        public class WsFed
        {
            public const string Prefix = "/wsfed";
            public const string ServiceName = "Fake ADFS";
            public const string DescriptorId = "_12345678-1234-1234-1234-123456789012";

            public const string Wa = "wa";
            public const string Wctx = "wctx";
            public const string Wresult = "wresult";
            public const string Wreply = "wreply";
            public const string Wtrealm = "wtrealm";
            public const string WSignIn = "wsignin1.0";
            public const string WSignOut = "wsignout1.0";

            public static class EndpointName
            {
                public const string Metadata = "Metadata";
                public const string PassiveRequestor = "PassiveRequestor";
            }

            public static class RoutePath
            {
                public const string Metadata = WsFed.Prefix + "/FederationMetadata/2007-06/FederationMetadata.xml";
                public const string EntityId = WsFed.Prefix + "/services/trust";
                public const string Mex = WsFed.Prefix + "/services/trust/mex";
                public const string MixedCertificateAddress = WsFed.Prefix + "/services/trust/2005/certificatemixed";
                public const string SingleLogoutLocation = WsFed.Prefix + "/ls";
                public const string SingleSignOnLocation = WsFed.Prefix + "/ls";
                public const string PassiveRequestor = WsFed.Prefix + "/ls";
            }
        }

        public class Saml
        {
            public const string Prefix = "/saml";
            public const string DescriptorId = "_12345678-1234-1234-1234-123456789012";
            public const string AuthResponseId = "_12345678-auth-response-id";
            public const string LogoutResponseId = "_12345678-logout-response-id";
            public const string AssertionIdPrefix = "assertion-id_";
            public const string SamlRequest = "SAMLRequest";
            public const string SamlResponse = "SAMLResponse";
            public const string RelayState = "RelayState";
            public const string UserId = "saml-user-id";

            public static class EndpointName
            {
                public const string Metadata = "SamlMetadata";
                public const string Login = "Login";
                public const string Logout = "Logout";
            }

            public static class RoutePath
            {
                public const string Metadata = Saml.Prefix + "/Metadata.xml";
                public const string SingleLogoutLocation = Saml.Prefix + "/logout";
                public const string Login = Saml.Prefix + "/login";
                public const string Logout = Saml.Prefix + "/logout";
                public const string LogoutResponseDestination = "/identity/AuthServices/Logout";
            }

            public static class ClaimName
            {
                public const string Email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
                public const string Name = "http://schemas.auth0.com/name";
                public const string Provider = "http://schemas.auth0.com/identities/default/provider";
                public const string Upn = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";
                public const string UserId = "http://schemas.auth0.com/identities/default/user_id";
            }
        }

        public static class ClaimType
        {
            public const string String = "string";
        }

        public static class CurveOids
        {
            public const string P256 = "1.2.840.10045.3.1.7";
            public const string P384 = "1.3.132.0.34";
            public const string P521 = "1.3.132.0.35";
        }

        public static class XmlNS
        {
            public const string Addressing = "http://www.w3.org/2005/08/addressing";
            public const string AssertionV1 = "urn:oasis:names:tc:SAML:1.0:assertion";
            public const string AssertionV2 = "urn:oasis:names:tc:SAML:2.0:assertion";
            public const string AttrNameFormatUri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
            public const string Bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
            public const string ClassesUnspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
            public const string Fed = "http://docs.oasis-open.org/wsfed/federation/200706";
            public const string Mex = "http://schemas.xmlsoap.org/ws/2004/09/mex";
            public const string NameIdFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
            public const string NameIdFormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
            public const string NameIdFormatTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
            public const string NameIdUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
            public const string NoProofKey = "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey";
            public const string PasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
            public const string Policy = "http://schemas.xmlsoap.org/ws/2004/09/policy";
            public const string PostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
            public const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
            public const string RedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
            public const string Saml2MetadataName = "urn:oasis:names:tc:SAML:2.0:metadata";
            public const string SecurityUtility = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
            public const string Success = "urn:oasis:names:tc:SAML:2.0:status:Success";
            public const string Trust = "http://schemas.xmlsoap.org/ws/2005/02/trust";
            public const string TrustIssue = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
            public const string XmlDSig = "http://www.w3.org/2000/09/xmldsig#";
            public const string XmlSchema = "http://www.w3.org/2001/XMLSchema";
            public const string XmlSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance";
        }

        public static class XmlNSName
        {
            public const string Fed = "fed";
            public const string Saml = "saml";
            public const string Samlp = "samlp";
            public const string Wsa = "wsa";
            public const string Wsp = "wsp";
            public const string Wst = "wst";
            public const string Wsu = "wsu";
            public const string Wsx = "wsx";
            public const string Xsd = "xsd";
            public const string Xsi = "xsi";
        }

        public static class XmlElementNames
        {
            public const string Address = "Address";
            public const string AppliesTo = "AppliesTo";
            public const string Assertion = "Assertion";
            public const string Attribute = "Attribute";
            public const string AttributeStatement = "AttributeStatement";
            public const string AttributeValue = "AttributeValue";
            public const string AudienceRestriction = "AudienceRestriction";
            public const string AudienceRestrictionCondition = "AudienceRestrictionCondition";
            public const string Audience = "Audience";
            public const string AuthenticationStatement = "AuthenticationStatement";
            public const string AuthnContext = "AuthnContext";
            public const string AuthnContextClassRef = "AuthnContextClassRef";
            public const string AuthnStatement = "AuthnStatement";
            public const string Created = "Created";
            public const string Conditions = "Conditions";
            public const string ConfirmationMethod = "ConfirmationMethod";
            public const string EndpointReference = "EndpointReference";
            public const string EntityDescriptor = "EntityDescriptor";
            public const string Expires = "Expires";
            public const string IDPSSODescriptor = "IDPSSODescriptor";
            public const string Issuer = "Issuer";
            public const string KeyDescriptor = "KeyDescriptor";
            public const string KeyInfo = "KeyInfo";
            public const string KeyType = "KeyType";
            public const string Lifetime = "Lifetime";
            public const string LogoutResponse = "LogoutResponse";
            public const string MetaData = "MetaData";
            public const string MetadataReference = "MetadataReference";
            public const string MetaDataSection = "MetaDataSection";
            public const string NameID = "NameID";
            public const string NameIdentifier = "NameIdentifier";
            public const string NameIdFormat = "NameIDFormat";
            public const string PassiveRequestorEndpoint = "PassiveRequestorEndpoint";
            public const string RequestedSecurityToken = "RequestedSecurityToken";
            public const string RequestSecurityTokenResponse = "RequestSecurityTokenResponse";
            public const string RequestType = "RequestType";
            public const string Response = "Response";
            public const string RoleDescriptor = "RoleDescriptor";
            public const string SecurityTokenServiceEndpoint = "SecurityTokenServiceEndpoint";
            public const string SingleLogoutService = "SingleLogoutService";
            public const string SingleSignOnService = "SingleSignOnService";
            public const string Status = "Status";
            public const string StatusCode = "StatusCode";
            public const string Subject = "Subject";
            public const string SubjectConfirmation = "SubjectConfirmation";
            public const string SubjectConfirmationData = "SubjectConfirmationData";
            public const string TokenType = "TokenType";
            public const string TokenTypesOffered = "TokenTypesOffered";
            public const string X509Certificate = "X509Certificate";
            public const string X509Data = "X509Data";
        }

        public static class XmlAttrNames
        {
            public const string AssertionId = "AssertionID";
            public const string AuthenticationMethod = "AuthenticationMethod";
            public const string AuthenticationInstant = "AuthenticationInstant";
            public const string AuthnInstant = "AuthnInstant";
            public const string Binding = "Binding";
            public const string Destination = "Destination";
            public const string Dialect = "Dialect";
            public const string EntityId = "entityID";
            public const string Format = "Format";
            public const string FriendlyName = "FriendlyName";
            public const string Id = "ID";
            public const string InResponseTo = "InResponseTo";
            public const string IssueInstant = "IssueInstant";
            public const string Issuer = "Issuer";
            public const string Location = "Location";
            public const string MajorVersion = "MajorVersion";
            public const string Method = "Method";
            public const string MinorVersion = "MinorVersion";
            public const string Name = "Name";
            public const string NameFormat = "NameFormat";
            public const string NotBefore = "NotBefore";
            public const string NotOnOrAfter = "NotOnOrAfter";
            public const string ProtocolSupportEnumeration = "protocolSupportEnumeration";
            public const string Recipient = "Recipient";
            public const string ServiceDisplayName = "ServiceDisplayName";
            public const string SessionIndex = "SessionIndex";
            public const string Type = "type";
            public const string Uri = "Uri";
            public const string Use = "use";
            public const string Value = "Value";
            public const string Version = "Version";
        }

        public static class XmlAttrValues
        {
            public const string Encryption = "encryption";
            public const string ProtocolSupportEnumeration = "http://docs.oasis-open.org/ws-sx/ws-trust/200512 http://schemas.xmlsoap.org/ws/2005/02/trust http://docs.oasis-open.org/wsfed/federation/200706";
            public const string SecurityTokenServiceType = "fed:SecurityTokenServiceType";
            public const string Signing = "signing";
            public const string V2_0 = "2.0";
        }

        public static class ClaimNames
        {
            public const string EmailAddress = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
            public const string GivenName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
            public const string Name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
            public const string NameIdentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
            public const string Upn = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";
        }

        public static class ClaimFriendlyNames
        {
            public const string EmailAddress = "E-Mail Address";
            public const string GivenName = "Given Name";
            public const string Name = "Name";
            public const string Upn = "UPN";
            public const string NameIdentifier = "Name ID";
        }
    }
}