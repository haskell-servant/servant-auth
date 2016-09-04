{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Auth.Server.Internal where

import Control.Monad.Trans (liftIO)
import Servant
import Servant.Auth

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
