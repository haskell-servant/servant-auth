module Servant.Auth.Server.Internal.AddSetCookie where

import           Blaze.ByteString.Builder (toByteString)
import           Crypto.Random
import           Crypto.Random.DRBG       (CtrDRBG)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Base64   as BS64
import           Data.Monoid
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
  AddedSetCookie (a :<|> b ) = AddedSetCookie a :<|> AddedSetCookie b
  {-AddedSetCookie (t (m old)) = t (AddedSetCookie (m old))-}
  AddedSetCookie (m old) = m (Headers '[Header "Set-Cookie" BS.ByteString] old)
  AddedSetCookie old = Headers '[Header "Set-Cookie" BS.ByteString] old

class AddSetCookie orig where
  addSetCookie :: [SetCookie] -> orig -> AddedSetCookie orig

instance {-# OVERLAPS #-} AddSetCookie oldb => AddSetCookie (a -> oldb) where
  addSetCookie cookie oldfn = \val -> addSetCookie cookie $ oldfn val

instance ( Functor m, AddSetCookie a, AddedSetCookie (m a) ~ m (AddedSetCookie a)
         ) => AddSetCookie (m a) where
  addSetCookie cookie v = addSetCookie cookie <$> v

instance (AddSetCookie a, AddSetCookie b) => AddSetCookie (a :<|> b) where
  addSetCookie cookie (a :<|> b) = addSetCookie cookie a :<|> addSetCookie cookie b

instance {-# OVERLAPPABLE #-}
  (AddedSetCookie old ~ Headers '[Header "Set-Cookie" BS.ByteString] old)
       => AddSetCookie old where
  addSetCookie cookie val
    -- What is happening here is sheer awfulness. Look the other way.
    = addHeader (foldr1 go
                $ toByteString . renderSetCookie <$> cookie) val
    :: Headers '[Header "Set-Cookie" BS.ByteString] old
    where
      go new old = old <> "\r\nSet-Cookie: " <> new


csrfCookie :: IO BS.ByteString
csrfCookie = do
   g <- newGenIO :: IO CtrDRBG
   case genBytes 16 g of
     Left e -> error $ show e
     Right (r, _) -> return $ BS64.encode r
