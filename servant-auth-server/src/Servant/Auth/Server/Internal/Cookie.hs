module Servant.Auth.Server.Internal.Cookie where

import Web.Cookie
import Servant.Auth.Server.Internal.Types


{-inCookieWithCSRF :: Request -> BS.ByteString -> CI (BS.ByteString) -> Handler Jose.JWT-}
{-inCookieWithCSRF req xsrfCookieName headerName = do-}
  {-cookies <- maybe (throwError err401) (return . parseCookies) $ lookup "Cookie" $ requestHeaders req-}
  {-xsrfCookie <- maybe (throwError err401) return $ lookup xsrfCookieName cookies-}
  {-xsrfHeader <- maybe (throwError err401) return $ lookup headerName $ requestHeaders req-}
  {-when (xsrfCookie /= xsrfHeader) $-}
    {-throwError err401 { errBody = "CSRF check failed" }-}
  {-jwtCookie <- maybe (throwError err401) return $ lookup "JWT-Cookie" cookies-}
  {-case Jose.decodeCompact $ BSL.fromStrict jwtCookie of-}
    {-Left (_ :: Jose.Error) -> throwError err401-}
    {-Right v -> return v-}

cookieAuthCheck :: AuthCheck usr
cookieAuthCheck = do
  req <- ask

