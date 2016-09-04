{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Auth.Server.Internal where

import Control.Monad.Trans (liftIO)
import Servant
import Servant.Auth
import Network.Wai (Response, mapResponseHeaders)
import Blaze.ByteString.Builder
import Web.Cookie

import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal.RoutingApplication

instance ( HasServer api ctxs, AreAuths auths ctxs v
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

  route _ context subserver =
    route (Proxy :: Proxy api) context (subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult v)
      authCheck = withRequest $ \req -> liftIO $
        runAuthCheck (runAuths (Proxy :: Proxy auths) context) req

instance ( HasServer api ctx, HasContextEntry ctx [SetCookie]
         ) => HasServer (SetCookies :> api) ctx where

  type ServerT (SetCookies :> api) m = ServerT api m
  route _ context subserver =
    tweakResponse setCookies $ route (Proxy :: Proxy api) context $ subserver
    where
      cookies :: [SetCookie]
      cookies = getContextEntry context

      header = toByteString $ foldMap renderSetCookie cookies

      setCookies :: RouteResult Response -> RouteResult Response
      setCookies (Route x) = Route $ mapResponseHeaders (("Set-Cookie", header):) x
      -- TODO: Should we set cookies in the FailFatal case as well? Presumably not
      -- in the Fail case though
      setCookies f         = f

