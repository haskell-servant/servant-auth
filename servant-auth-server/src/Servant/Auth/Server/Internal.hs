{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Auth.Server.Internal where

import           Blaze.ByteString.Builder
import           Control.Monad.Trans      (liftIO)
import qualified Crypto.JOSE              as Jose
import qualified Crypto.JWT               as Jose
import qualified Data.ByteString.Lazy     as BSL
import qualified Data.ByteString.Char8    as BSC
import           Data.Reflection
import           Network.Wai              (Response, mapResponseHeaders)
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
         , ServerT (AddSetCookieApi api) Handler ~ AddedSetCookie (ServerT api Handler)
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookieApi api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult v)
      authCheck = withRequest $ \req -> liftIO $
        runAuthCheck (runAuths (Proxy :: Proxy auths) context) req

      go :: AddSetCookie old => (AuthResult v -> old) -> AuthResult v -> AddedSetCookie old
      go fn authResult = addSetCookie undefined $ fn authResult
