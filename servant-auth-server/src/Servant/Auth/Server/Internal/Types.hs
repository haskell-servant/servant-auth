module Servant.Auth.Server.Internal.Types where

import Control.Applicative
import Control.Monad.Reader
import Control.Monad.Time
import Data.Monoid
import Data.Time            (getCurrentTime)
import GHC.Generics         (Generic)
import Network.Wai          (Request)

data AuthResult val
  = BadPassword
  | NoSuchUser
  | Authenticated val
  | Indefinite
  deriving (Eq, Show, Read, Generic, Ord, Functor)

instance Monoid (AuthResult val) where
  mempty = Indefinite
  Indefinite `mappend` x = x
  x `mappend` _ = x

instance Monad AuthResult where
  return = Authenticated
  Authenticated v >>= f = f v
  BadPassword  >>= _ = BadPassword
  NoSuchUser   >>= _ = NoSuchUser
  Indefinite   >>= _ = Indefinite

instance Applicative AuthResult where
  pure = return
  (<*>) = ap

newtype AuthCheck val = AuthCheck
  { runAuthCheck :: Request -> IO (AuthResult val) }
  deriving (Generic, Functor)

instance Monoid (AuthCheck val) where
  mempty = AuthCheck $ const $ return mempty
  AuthCheck f `mappend` AuthCheck g = AuthCheck $ \x -> do
    fx <- f x
    gx <- g x
    return $ fx <> gx

instance Applicative AuthCheck where
  pure = return
  (<*>) = ap

instance Monad AuthCheck where
  return = AuthCheck . return . return . return
  fail _ = AuthCheck . const $ return Indefinite
  AuthCheck ac >>= f = AuthCheck $ \req -> do
    aresult <- ac req
    case aresult of
      Authenticated usr -> runAuthCheck (f usr) req
      BadPassword       -> return BadPassword
      NoSuchUser        -> return NoSuchUser
      Indefinite        -> return Indefinite

instance MonadReader Request AuthCheck where
  ask = AuthCheck $ \x -> return (Authenticated x)
  local f (AuthCheck check) = AuthCheck $ \req -> check (f req)

instance MonadIO AuthCheck where
  liftIO action = AuthCheck $ const $ Authenticated <$> action

instance MonadTime AuthCheck where
  currentTime = liftIO $ getCurrentTime

instance Alternative AuthCheck where
  empty = mzero
  (<|>) = mplus

instance MonadPlus AuthCheck where
  mzero = mempty
  mplus = (<>)
