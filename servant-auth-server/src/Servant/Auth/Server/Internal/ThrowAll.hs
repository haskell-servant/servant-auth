{-# LANGUAGE UndecidableInstances #-}
module Servant.Auth.Server.Internal.ThrowAll where

import Control.Monad.Error.Class
import Servant                   ((:<|>) (..), ServantErr)

class ThrowAll a where
  -- | 'throwAll' is a convenience function to throw errors across an entire
  -- sub-API
  --
  --
  -- > throwAll err400 :: Handler a :<|> Handler b :<|> Handler c
  -- >    == throwError err400 :<|> throwError err400 :<|> err400
  throwAll :: ServantErr -> a

instance (ThrowAll a, ThrowAll b) => ThrowAll (a :<|> b) where
  throwAll e = throwAll e :<|> throwAll e

-- Really this shouldn't be necessary - ((->) a) should be an instance of
-- MonadError, no?
instance {-# OVERLAPS #-} ThrowAll b => ThrowAll (a -> b) where
  throwAll e = const $ throwAll e

instance {-# OVERLAPPABLE #-} (MonadError ServantErr m) => ThrowAll (m a) where
  throwAll = throwError
