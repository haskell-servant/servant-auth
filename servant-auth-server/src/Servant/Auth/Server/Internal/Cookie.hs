module Servant.Auth.Server.Internal.Cookie where

import           Blaze.ByteString.Builder  (toByteString)
import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE               as Jose
import qualified Crypto.JWT                as Jose
import           Crypto.Util               (constTimeEq)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Lazy      as BSL
import           Data.CaseInsensitive      (mk)
import           Network.HTTP.Types.Method (StdMethod(..), parseMethod)
import           Network.Wai               (Request, requestHeaders,
                                            requestMethod)
import           Web.Cookie

import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT         (FromJWT (decodeJWT), ToJWT,
                                                 makeJWT)
import Servant.Auth.Server.Internal.Types


statelessReq :: Request -> Bool
statelessReq req = case parseMethod $ requestMethod req of
  Left _ -> False
  Right method -> case method of
    GET -> True
    HEAD -> True
    OPTIONS -> True
    TRACE -> True
    _ -> False

cookieAuthCheck :: FromJWT usr => CookieSettings -> JWTSettings -> AuthCheck usr
cookieAuthCheck ccfg jwtCfg = do
  req <- ask
  let headers = requestHeaders req
  cookies' <- maybeToAuthCheck $ lookup "Cookie" headers
  let cookies = parseCookies cookies'
  jwtCookie <- maybeToAuthCheck $ lookup "JWT-Cookie" cookies
  unless (statelessReq req) $ maybeToAuthCheck $ do
    xsrfCookie <- lookup (xsrfCookieName ccfg) cookies
    xsrfHeader <- lookup (mk $ xsrfHeaderName ccfg) headers
    guard $ xsrfCookie `constTimeEq` xsrfHeader
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict jwtCookie
    Jose.validateJWSJWT (jwtSettingsToJwtValidationSettings jwtCfg)
                        (key jwtCfg)
                         unverifiedJWT
    return unverifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'

  where
    maybeToAuthCheck :: Maybe a -> AuthCheck a
    maybeToAuthCheck = maybe mempty return

makeCookie :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe SetCookie)
makeCookie cookieSettings jwtSettings v = do
  ejwt <- makeJWT v jwtSettings Nothing
  case ejwt of
    Left _ -> return Nothing
    Right jwt -> return $ Just $ def
        { setCookieName = "JWT-Cookie"
        , setCookieValue = BSL.toStrict jwt
        , setCookieHttpOnly = True
        , setCookieMaxAge = cookieMaxAge cookieSettings
        , setCookieExpires = cookieExpires cookieSettings
        , setCookieSecure = case cookieIsSecure cookieSettings of
            Secure -> True
            NotSecure -> False
        }

makeCookieBS :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe BS.ByteString)
makeCookieBS a b c = fmap (toByteString . renderSetCookie)  <$> makeCookie a b c
