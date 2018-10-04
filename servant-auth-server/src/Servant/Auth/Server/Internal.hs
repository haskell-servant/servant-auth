{-# LANGUAGE CPP #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Internal where

import           Control.Monad.Trans (liftIO)
import           Servant             ((:>), Handler, HasServer (..),
                                      Proxy (..))
import           Servant.Auth

import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal.RoutingApplication


instance ( AreAuths auths ctxs v
         , HasServer api ctxs -- this constraint is needed to implement hoistServer
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

#if MIN_VERSION_servant_server(0,12,0)
  hoistServerWithContext _ pc nt s = hoistServerWithContext (Proxy :: Proxy api) pc nt . s
#endif

  route _ context subserver =
    route (Proxy :: Proxy api)
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult v)
      authCheck = withRequest $ \req -> liftIO $ do
        authResult <- runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        return (authResult)

      go :: ( old ~ ServerT api Handler
            , new ~ ServerT api Handler
            )
         => (AuthResult v -> ServerT api Handler)
         -> (AuthResult v) -> new
      go fn (authResult) = fn authResult
