{-# LANGUAGE CPP #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Internal where

import           Control.Monad.Trans (liftIO)
import           Servant             ((:>), Handler, HasServer (..),
                                      Proxy (..),
                                      HasContextEntry(getContextEntry))
import           Servant.Auth

import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT

import Servant.Server.Internal.RoutingApplication

instance ( n ~ 'S ('S 'Z)
         , HasServer (AddSetCookiesApi n api) ctxs, AreAuths auths ctxs v
         , HasServer api ctxs -- this constraint is needed to implement hoistServer
         , AddSetCookies n (ServerT api Handler) (ServerT (AddSetCookiesApi n api) Handler)
         , ToJWT v
         , HasContextEntry ctxs CookieSettings
         , HasContextEntry ctxs JWTSettings
         ) => HasServer (Auth auths v :> api) ctxs where

  type ServerT (Auth auths v :> api) m = AuthResult auths v -> ServerT api m

#if MIN_VERSION_servant_server(0,12,0)
  hoistServerWithContext _ pc nt s = hoistServerWithContext (Proxy :: Proxy api) pc nt . s
#endif

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookiesApi n api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult auths v, SetCookieList ('S ('S 'Z)))
      authCheck = withRequest $ \req -> liftIO $ do
        authResult <- runAuths (Proxy :: Proxy auths) context req
        cookies <- makeCookies authResult
        return (authResult, cookies)

      jwtSettings :: JWTSettings
      jwtSettings = getContextEntry context

      cookieSettings :: CookieSettings
      cookieSettings = getContextEntry context

      makeCookies :: AuthResult auths v -> IO (SetCookieList ('S ('S 'Z)))
      makeCookies authResult = do
        csrf <- makeCsrfCookie cookieSettings
        fmap (Just csrf `SetCookieCons`) $
          case authResult of
            Authenticated v -> do
              ejwt <- makeSessionCookie cookieSettings jwtSettings v
              case ejwt of
                Nothing  -> return $ Nothing `SetCookieCons` SetCookieNil
                Just jwt -> return $ Just jwt `SetCookieCons` SetCookieNil
            _ -> return $ Nothing `SetCookieCons` SetCookieNil

      go :: ( old ~ ServerT api Handler
            , new ~ ServerT (AddSetCookiesApi n api) Handler
            )
         => (AuthResult auths v -> ServerT api Handler)
         -> (AuthResult auths v, SetCookieList n) -> new
      go fn (authResult, cookies) = addSetCookies cookies $ fn authResult
