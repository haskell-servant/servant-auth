module Servant.Auth.Server.Internal.ConfigTypes where

import           Crypto.JOSE        as Jose
import           Crypto.JWT         as Jose
import qualified Data.ByteString    as BS
import           Data.Default.Class
import           Data.Time
import           GHC.Generics       (Generic)
import           Network.Wai        (Request)

data IsMatch = Matches | DoesNotMatch
  deriving (Eq, Show, Read, Generic, Ord)

data IsSecure = Secure | NotSecure
  deriving (Eq, Show, Read, Generic, Ord)

data IsPasswordCorrect = PasswordCorrect | PasswordIncorrect
  deriving (Eq, Show, Read, Generic, Ord)

-- The @SameSite@ attribute of cookies determines whether cookies will be sent
-- on cross-origin requests.
--
-- See <https://tools.ietf.org/html/draft-west-first-party-cookies-07 this document>
-- for more information.
data SameSite = AnySite | SameSiteStrict | SameSiteLax
  deriving (Eq, Show, Read, Generic, Ord)

-- | @JWTSettings@ are used to generate cookies, and to verify JWTs.
data JWTSettings = JWTSettings
  { key             :: Jose.JWK
  -- | An @aud@ predicate. The @aud@ is a string or URI that identifies the
  -- intended recipient of the JWT.
  , audienceMatches :: Jose.StringOrURI -> IsMatch
  } deriving (Generic)

-- | A @JWTSettings@ where the audience always matches.
defaultJWTSettings :: Jose.JWK -> JWTSettings
defaultJWTSettings k = JWTSettings { key = k, audienceMatches = const Matches }

-- | The policies to use when generating cookies.
--
-- If *both* 'cookieMaxAge' and 'cookieExpires' are @Nothing@, browsers will
-- treat the cookie as a *session cookie*. These will be deleted when the
-- browser is closed.
--
-- Note that having the setting @Secure@ may cause testing failures if you are
-- not testing over HTTPS.
data CookieSettings = CookieSettings
  {
  -- | 'Secure' means browsers will only send cookies over HTTPS. Default:
  -- @Secure@.
    cookieIsSecure          :: !IsSecure
  -- | How long from now until the cookie expires. Default: @Nothing@.
  , cookieMaxAge            :: !(Maybe DiffTime)
  -- | At what time the cookie expires. Default: @Nothing@.
  , cookieExpires           :: !(Maybe UTCTime)
  -- | The URL path and sub-paths for which this cookie is used. Default @Just "/"@.
  , cookiePath              :: !(Maybe BS.ByteString)
  -- | 'SameSite' settings. Default: @SameSiteLax@.
  , cookieSameSite          :: !SameSite
  -- | What name to use for the cookie used for the session.
  , cookieSessionCookieName :: !BS.ByteString
  -- | The optional settings to use for XSRF protection. Default @Just def@.
  , cookieXsrfSetting       :: !(Maybe XsrfCookieSettings)
  -- | An arbitrary check for the request. Use this to implement validating
  --   the Origin/Referer headers. Default @const True@.
  , cookieCheckRequest      :: !(Request -> Bool)
  } deriving (Generic)

instance Default CookieSettings where
  def = defaultCookieSettings

defaultCookieSettings :: CookieSettings
defaultCookieSettings = CookieSettings
  { cookieIsSecure          = Secure
  , cookieMaxAge            = Nothing
  , cookieExpires           = Nothing
  , cookiePath              = Just "/"
  , cookieSameSite          = SameSiteLax
  , cookieSessionCookieName = "JWT-Cookie"
  , cookieXsrfSetting       = Just def
  , cookieCheckRequest      = const True
  }


-- | The policies to use when generating and verifying XSRF cookies
data XsrfCookieSettings = XsrfCookieSettings
  {
  -- | What name to use for the cookie used for CSRF protection.
    xsrfCookieName :: !BS.ByteString
  -- | What path to use for the cookie used for CSRF protection. Default @Just "/"@.
  , xsrfCookiePath :: !(Maybe BS.ByteString)
  -- | What name to use for the header used for CSRF protection.
  , xsrfHeaderName :: !BS.ByteString
  } deriving (Eq, Show, Generic)

instance Default XsrfCookieSettings where
  def = defaultXsrfCookieSettings

defaultXsrfCookieSettings :: XsrfCookieSettings
defaultXsrfCookieSettings = XsrfCookieSettings
  { xsrfCookieName = "XSRF-TOKEN"
  , xsrfCookiePath = Just "/"
  , xsrfHeaderName = "X-XSRF-TOKEN"
  }


------------------------------------------------------------------------------
-- Internal {{{

jwtSettingsToJwtValidationSettings :: JWTSettings -> Jose.JWTValidationSettings
jwtSettingsToJwtValidationSettings s
  = defaultJWTValidationSettings (toBool <$> audienceMatches s)
  where
    toBool Matches      = True
    toBool DoesNotMatch = False
-- }}}
