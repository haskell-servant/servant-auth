{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Auth.Server.Internal where

import           Control.Monad.Trans      (liftIO)
import qualified Crypto.JOSE              as Jose
import qualified Crypto.JWT               as Jose
import qualified Data.ByteString.Lazy     as BSL
import           Servant
import           Servant.Auth
import qualified Web.Cookie               as Cookie

import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.AddSetCookie

import Servant.Server.Internal.RoutingApplication

instance ( HasServer (AddSetCookieApi api) ctxs, AreAuths auths ctxs v
         , AddSetCookie (ServerT api Handler)
         , ToJWT v
         , HasContextEntry ctxs Jose.JWK
         , ServerT (AddSetCookieApi api) Handler ~ AddedSetCookie (ServerT api Handler)
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookieApi api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult v, [Cookie.SetCookie])
      authCheck = withRequest $ \req -> liftIO $ do
        authResult <- runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        csrf' <- csrfCookie
        let csrf = Cookie.def
             { Cookie.setCookieName = "XSRF-TOKEN"
             , Cookie.setCookieValue = csrf'
             }
        cookies <- makeCookies authResult
        return (authResult, csrf : cookies )

      key :: Jose.JWK
      key = getContextEntry context

      makeCookies :: AuthResult v -> IO [Cookie.SetCookie]
      makeCookies (Authenticated v) = do
        ejwt <- Jose.createJWSJWT key (Jose.newJWSHeader (Jose.Protected, Jose.HS256))
                              (encodeJWT v)
        case ejwt >>= Jose.encodeCompact of
            Left _ -> return []
            Right jwt -> return [Cookie.def { Cookie.setCookieName = "JWT-Cookie"
                                            , Cookie.setCookieValue = BSL.toStrict jwt
                                            , Cookie.setCookieHttpOnly = True
                                            }]
      makeCookies _ = return []


      go :: AddSetCookie old => (AuthResult v -> old)
         -> (AuthResult v, [Cookie.SetCookie]) -> AddedSetCookie old
      go fn (authResult, csrf) = addSetCookie csrf $ fn authResult
