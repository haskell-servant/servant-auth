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

{-
instance ( HasServer api ctx, HasContextEntry ctx v
         , ToJWT v
         , Reifies isHttpOnly IsHttpOnly
         , Reifies isSecure Servant.Auth.IsSecure
         , Reifies cookieName String
         ) => HasServer (SetCookie cookieName isSecure isHttpOnly v :> api) ctx where

  type ServerT (SetCookie cookieName isSecure isHttpOnly v :> api) m = ServerT api m
  route _ context subserver =
    tweakResponse setCookies $ route (Proxy :: Proxy api) context $ subserver
    where
      value :: v
      value = getContextEntry context

      cookies :: Cookie.SetCookie
      cookies = case Jose.createJWSJWT (encodeJWT value) >>= Jose.encodeCompact of
        Left (_ :: Jose.Error) -> Cookie.def -- TODO. Really, types should be
                                             -- such that this doesn't happen
        Right v -> Cookie.def
          { Cookie.setCookieValue = BSL.toStrict v
          , Cookie.setCookieName = BSC.pack $ reflect (Proxy :: Proxy cookieName)
          , Cookie.setCookieSecure = reflect (Proxy :: Proxy isSecure)
                                  == Servant.Auth.Secure
          , Cookie.setCookieHttpOnly = reflect (Proxy :: Proxy isHttpOnly) == HttpOnly

        }

      header = toByteString $ Cookie.renderSetCookie cookies

      setCookies :: RouteResult Response -> RouteResult Response
      setCookies (Route x) = Route $ mapResponseHeaders (("Set-Cookie", header):) x
      -- TODO: Should we set cookies in the FailFatal case as well? Presumably not
      -- in the Fail case though
      setCookies f         = f
      -}
