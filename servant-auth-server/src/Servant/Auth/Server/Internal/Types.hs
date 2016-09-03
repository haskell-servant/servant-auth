module Servant.Auth.Server.Internal.Types where

{-import Control.Monad (ap)-}
import Network.Wai (Request)
import GHC.Generics (Generic)
import Data.Monoid
import Control.Monad.Reader

data AuthResult val
  = BadPassword
  | NoSuchUser
  | Authorized val
  | Indefinite
  deriving (Eq, Show, Read, Generic, Ord, Functor)

instance Monoid (AuthResult val) where
  mempty = Indefinite
  Indefinite `mappend` x = x
  x `mappend` _ = x

instance Monad AuthResult where
  return = Authorized
  Authorized v >>= f = f v
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
  AuthCheck ac >>= f = AuthCheck $ \req -> do
    aresult <- ac req
    case aresult of
      Authorized usr -> runAuthCheck (f usr) req
      BadPassword    -> return BadPassword
      NoSuchUser     -> return NoSuchUser
      Indefinite     -> return Indefinite

instance MonadReader Request AuthCheck where
  ask = AuthCheck $ \x -> return (Authorized x)
  local f (AuthCheck check) = AuthCheck $ \req -> check (f req)
