{-# LANGUAGE CPP #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Internal where

import           Control.Monad.Trans (liftIO)
import           Servant             ((:>), Handler, HasServer (..),
                                      Proxy (..),
                                      HasContextEntry(getContextEntry))
import           Servant.Auth
import           Servant.Auth.JWT    (ToJWT)

import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal (DelayedIO, addAuthCheck, withRequest)

instance ( n ~ 'S ('S 'Z)
         , HasServer (AddSetCookiesApi n api) ctxs, AreAuths auths ctxs v
         , HasServer api ctxs -- this constraint is needed to implement hoistServer
         , AddSetCookies n (ServerT api Handler) (ServerT (AddSetCookiesApi n api) Handler)
         , ToJWT v
         , HasContextEntry ctxs CookieSettings
         , HasContextEntry ctxs JWTSettings
         , HasContextEntry ctxs AuthErrorHandler
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = v -> ServerT api m

#if MIN_VERSION_servant_server(0,12,0)
  hoistServerWithContext _ pc nt s = hoistServerWithContext (Proxy :: Proxy api) pc nt . s
#endif

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookiesApi n api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (v, SetCookieList ('S ('S 'Z)))
      authCheck = withRequest $ \req -> do
        authResult <- liftIO $ runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        cookies <- liftIO $ makeCookies authResult
        authVal <- authErrHandler authResult
        return (authVal, cookies)

      jwtSettings :: JWTSettings
      jwtSettings = getContextEntry context

      cookieSettings :: CookieSettings
      cookieSettings = getContextEntry context

      authErrHandler :: AuthResult v -> DelayedIO v
      authErrHandler = getAuthErrorHandler $ getContextEntry context

      makeCookies :: AuthResult v -> IO (SetCookieList ('S ('S 'Z)))
      makeCookies authResult = do
        xsrf <- makeXsrfCookie cookieSettings
        fmap (Just xsrf `SetCookieCons`) $
          case authResult of
            (Authenticated v) -> do
              ejwt <- makeSessionCookie cookieSettings jwtSettings v
              case ejwt of
                Nothing  -> return $ Nothing `SetCookieCons` SetCookieNil
                Just jwt -> return $ Just jwt `SetCookieCons` SetCookieNil
            _ -> return $ Nothing `SetCookieCons` SetCookieNil

      go :: (v -> ServerT api Handler)
         -> (v, SetCookieList n)
         -> ServerT (AddSetCookiesApi n api) Handler
      go fn (authVal, cookies) = addSetCookies cookies $ fn authVal
