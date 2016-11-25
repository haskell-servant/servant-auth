{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Internal where

import           Control.Monad.Trans  (liftIO)
import           Servant              ((:>), Handler, HasServer (..),
                                       Proxy (..), HasContextEntry(getContextEntry))
import           Servant.Auth
import qualified Web.Cookie           as Cookie

import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal.RoutingApplication

instance ( n ~ S (S Z)
         , HasServer (AddSetCookiesApi n api) ctxs, AreAuths auths ctxs v
         , AddSetCookies n (ServerT api Handler) (ServerT (AddSetCookiesApi n api) Handler)
         , ToJWT v
         , HasContextEntry ctxs CookieSettings
         , HasContextEntry ctxs JWTSettings
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookiesApi n api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult v, SetCookieList (S (S Z)) )
      authCheck = withRequest $ \req -> liftIO $ do
        authResult <- runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        csrf' <- csrfCookie
        let csrf = Cookie.def
             { Cookie.setCookieName = xsrfCookieName cookieSettings
             , Cookie.setCookieValue = csrf'
             , Cookie.setCookieMaxAge = cookieMaxAge cookieSettings
             , Cookie.setCookieExpires = cookieExpires cookieSettings
             , Cookie.setCookieSecure = case cookieIsSecure cookieSettings of
                  Secure -> True
                  NotSecure -> False
             }
        cookies <- makeCookies authResult
        return (authResult, csrf `SCCons` cookies)

      jwtSettings :: JWTSettings
      jwtSettings = getContextEntry context

      cookieSettings :: CookieSettings
      cookieSettings = getContextEntry context

      makeCookies :: AuthResult v -> IO (SetCookieList (S Z))
      makeCookies (Authenticated v) = do
        ejwt <- makeCookie cookieSettings jwtSettings v
        case ejwt of
            Just jwt -> return $ jwt `SCCons` SCNil


      -- See note in AddSetCookie.hs about what this is doing.
      go :: ( n ~ S (S Z)
            , old ~ ServerT api Handler
            , new ~ ServerT (AddSetCookiesApi n api) Handler
            , AddSetCookies n old new)
         => (AuthResult v -> ServerT api Handler)
         -> (AuthResult v, SetCookieList n) -> new
      go fn (authResult, cookies) = addSetCookies cookies $ fn authResult
