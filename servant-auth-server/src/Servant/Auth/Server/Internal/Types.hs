module Servant.Auth.Server.Internal.Types where

import Control.Applicative
import Control.Monad.Reader
import Control.Monad.Time
import Data.Semigroup
import Data.Time            (getCurrentTime)
import GHC.Generics         (Generic)
import Network.Wai          (Request)

-- | The result of an authentication attempt.
data AuthResult val
  = BadPassword
  | NoSuchUser
  -- | Authentication succeeded.
  | Authenticated val
  -- | If an authentication procedure cannot be carried out - if for example it
  -- expects a password and username in a header that is not present -
  -- @Indefinite@ is returned. This indicates that other authentication
  -- methods should be tried.
  | Indefinite [String]
  deriving (Eq, Show, Read, Generic, Ord, Functor, Traversable, Foldable)

instance Semigroup (AuthResult val) where
  Authenticated v <> _ = Authenticated v
  _ <> Authenticated v = Authenticated v
  Indefinite e <> Indefinite e' = Indefinite $ e ++ e'
  Indefinite _ <> x = x
  x <> _ = x

instance Monoid (AuthResult val) where
  mempty = fail "mempty"
  mappend = (<>)

instance Applicative AuthResult where
  pure = Authenticated
  (<*>) = ap

instance Monad AuthResult where
  return = pure
  fail = Indefinite . pure
  Authenticated v >>= f = f v
  BadPassword  >>= _ = BadPassword
  NoSuchUser   >>= _ = NoSuchUser
  Indefinite e >>= _ = Indefinite e

instance Alternative AuthResult where
  empty = fail "empty"
  (<|>) = mplus

instance MonadPlus AuthResult where
  mzero = fail "mzero"
  mplus = (<>)


-- | An @AuthCheck@ is the function used to decide the authentication status
-- (the 'AuthResult') of a request. Different @AuthCheck@s may be combined as a
-- Monoid or Alternative; the semantics of this is that the *first*
-- non-'Indefinite' result from left to right is used.
newtype AuthCheck val = AuthCheck
  { runAuthCheck :: Request -> IO (AuthResult val) }
  deriving (Generic, Functor)

instance Semigroup (AuthCheck val) where
  AuthCheck f <> AuthCheck g = AuthCheck $ \x -> do
    fx <- f x
    gx <- g x
    return $ fx <> gx

instance Monoid (AuthCheck val) where
  mempty = AuthCheck $ const $ return mempty
  mappend = (<>)

instance Applicative AuthCheck where
  pure = AuthCheck . pure . pure . pure
  (<*>) = ap

instance Monad AuthCheck where
  return = pure
  fail e = AuthCheck . const $ return $ Indefinite [e]
  AuthCheck ac >>= f = AuthCheck $ \req -> do
    aresult <- ac req
    case aresult of
      Authenticated usr -> runAuthCheck (f usr) req
      BadPassword       -> return BadPassword
      NoSuchUser        -> return NoSuchUser
      Indefinite e      -> return $ Indefinite e

instance MonadReader Request AuthCheck where
  ask = AuthCheck $ \x -> return (Authenticated x)
  local f (AuthCheck check) = AuthCheck $ \req -> check (f req)

instance MonadIO AuthCheck where
  liftIO action = AuthCheck $ const $ Authenticated <$> action

instance MonadTime AuthCheck where
  currentTime = liftIO getCurrentTime

instance Alternative AuthCheck where
  empty = mzero
  (<|>) = mplus

instance MonadPlus AuthCheck where
  mzero = mempty
  mplus = (<>)
