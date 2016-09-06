module Servant.Auth.Server.Internal.AddSetCookie where

import           Blaze.ByteString.Builder (toByteString)
import qualified Data.ByteString          as BS
import Crypto.Random
import Crypto.Random.DRBG (CtrDRBG)
import qualified Data.ByteString.Base64 as BS64
import           Servant
import           Web.Cookie

type family AddSetCookieApi a where
  AddSetCookieApi (a :> b) = a :> AddSetCookieApi b
  AddSetCookieApi (a :<|> b) = AddSetCookieApi a :<|> AddSetCookieApi b
  AddSetCookieApi (m a) = m (Headers '[Header "Set-Cookie" BS.ByteString] a)
  AddSetCookieApi (Headers ls a) = Headers ((Header "Set-Cookie" BS.ByteString) ': ls) a
  AddSetCookieApi a = Headers '[Header "Set-Cookie" BS.ByteString] a


type family AddedSetCookie a where
  AddedSetCookie (a -> b) = a -> AddedSetCookie b
  AddedSetCookie (t (m old)) = t (AddedSetCookie (m old))
  AddedSetCookie (m old) = m (AddedSetCookie old)
  AddedSetCookie old = Headers '[Header "Set-Cookie" BS.ByteString] old

class AddSetCookie orig where
  addSetCookie :: [SetCookie] -> orig -> AddedSetCookie orig

instance {-# OVERLAPS #-} AddSetCookie oldb => AddSetCookie (a -> oldb) where
  addSetCookie cookie oldfn = \val -> addSetCookie cookie $ oldfn val

instance (Functor m, AddSetCookie a) => AddSetCookie (m a) where
  addSetCookie cookie v = addSetCookie cookie <$> v

instance {-# OVERLAPPABLE #-}
  (AddedSetCookie old ~ Headers '[Header "Set-Cookie" BS.ByteString] old)
       => AddSetCookie old where
  addSetCookie cookie val
    = addHeader (toByteString $ foldMap renderSetCookie cookie) val :: Headers '[Header "Set-Cookie" BS.ByteString] old


csrfCookie :: IO BS.ByteString
csrfCookie = do
   g <- newGenIO :: IO CtrDRBG
   case genBytes 16 g of
     Left e -> error $ show e
     Right (r, _) -> return $ BS64.encode r
