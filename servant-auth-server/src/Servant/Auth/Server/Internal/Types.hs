{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilyDependencies #-}
{-# LANGUAGE UndecidableInstances #-}
module Servant.Auth.Server.Internal.Types where

import Control.Monad.Reader
import Control.Monad.Time
import Data.Time            (getCurrentTime)
import GHC.Generics         (Generic)
import Network.Wai          (Request)

-- | An @AuthCheck@ is the function used to decide the authentication status
-- of a request.
newtype AuthCheck err val = AuthCheck
  { runAuthCheck :: Request -> IO (Either err val) }
  deriving (Generic, Functor)

instance Applicative (AuthCheck err) where
  pure = AuthCheck . pure . pure . pure
  (<*>) = ap

failWith :: err -> AuthCheck err a
failWith = AuthCheck . const . pure . Left

instance Monad (AuthCheck err) where
  return = pure
  AuthCheck ac >>= f = AuthCheck $ \req -> do
    aresult <- ac req
    case aresult of
      Right usr -> runAuthCheck (f usr) req
      Left e -> pure $ Left e

instance MonadReader Request (AuthCheck err) where
  ask = AuthCheck $ pure . Right
  local f (AuthCheck check) = AuthCheck $ \req -> check (f req)

instance MonadIO (AuthCheck err) where
  liftIO action = AuthCheck $ const $ Right <$> action

instance MonadTime (AuthCheck err) where
  currentTime = liftIO getCurrentTime

