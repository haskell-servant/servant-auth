module Servant.Auth.Server.Internal.ConfigTypes where

import           Control.Lens
import           Crypto.JOSE        as Jose
import           Crypto.JWT         as Jose
import qualified Data.ByteString    as BS
import           Data.Default.Class
import           Data.Time
import           GHC.Generics       (Generic)


data IsMatch = Matches | DoesNotMatch
  deriving (Eq, Show, Read, Generic, Ord)

data IsSecure = Secure | NotSecure
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
   cookieIsSecure :: IsSecure
  -- | How long from now until the cookie expires. Default: @Nothing@
  , cookieMaxAge   :: Maybe DiffTime
  -- | At what time the cookie expires. Default: @Nothing@
  , cookieExpires  :: Maybe UTCTime
  -- | 'SameSite' settings. Default: @SameSiteLax@.
  , cookieSameSite :: SameSite
  -- | What name to use for the cookie used for CSRF protection.
  , xsrfCookieName :: BS.ByteString
  -- | What name to use for the header used for CSRF protection.
  , xsrfHeaderName :: BS.ByteString
  } deriving (Eq, Show, Generic)

instance Default CookieSettings where
  def = defaultCookieSettings

defaultCookieSettings :: CookieSettings
defaultCookieSettings = CookieSettings
    { cookieIsSecure = Secure
    , cookieMaxAge   = Nothing
    , cookieExpires  = Nothing
    , cookieSameSite = SameSiteLax
    , xsrfCookieName = "XSRF-TOKEN"
    , xsrfHeaderName = "X-XSRF-TOKEN"
    }

------------------------------------------------------------------------------
-- Internal {{{

jwtSettingsToJwtValidationSettings :: JWTSettings -> Jose.JWTValidationSettings
jwtSettingsToJwtValidationSettings s
  = defaultJWTValidationSettings
       & audiencePredicate .~ (toBool <$> audienceMatches s)
  where
    toBool Matches = True
    toBool DoesNotMatch = False
-- }}}
