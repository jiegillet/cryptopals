{-# LANGUAGE OverloadedStrings #-}

import           Encodings
import           AES128
import           Set1
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C hiding (ByteString)
import           System.Random
import           Control.Exception
import           Control.Monad (filterM)
import           Data.Function (on)
import           Data.Bits
import           Data.List (maximumBy, unfoldr, tails)
import           Data.Time.Clock.POSIX
import           Test.QuickCheck (quickCheck)

-- Ex 17

messages = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

validPadding :: (ByteString -> ByteString) -> ByteString -> IO Bool
validPadding _ "" = return True
validPadding decoder cypher = catch (decoder cypher `seq` return True) oops
  where oops :: EncodingException -> IO Bool
        oops e = return False

breakCBC :: ByteString -> ByteString -> (ByteString -> IO Bool) -> IO ByteString
breakCBC cyphertext iv check = do
  let s = B.length iv
      b = chunksOf s cyphertext
  blocks <- sequence $ zipWith (breakBlock s check) (iv:b) b
  return $ B.concat blocks

breakBlock :: Int64 -> (ByteString -> IO Bool) -> ByteString -> ByteString -> IO ByteString
breakBlock s check b1 b2 = getByte (s-1) ""
  where
  getByte (-1) bytes = return bytes
  getByte i bytes = do
    let rep = B.replicate
        tryByte z = let a = B.append (rep i 0) (B.cons z bytes)
                        b = B.append (rep i 0) (rep (s-i) (fromIntegral (s-i)))
                    in B.append (xorB b1 (xorB a b)) b2
    sol <- filterM (check . tryByte) [0..255]
    if null sol
    then return ""
    else B.concat <$> mapM (\x -> getByte (i-1) (B.cons x bytes)) sol

ex17 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  iv <- B.pack . take 16 . randoms <$> newStdGen
  msg <- randomRIO (0,9)
  let cyphertext = encodeAES128CBC key iv $ base64ToByteString (messages!!msg)
      check = validPadding (decodeAES128CBC key iv)
  plain <- breakCBC cyphertext iv check
  print $ stripPkcs7 16 plain

-- Ex 18

ex18 = do
  let key = "YELLOW SUBMARINE"
      seed = (0, 0)
      txt = base64ToByteString "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
  print $ decodeAES128CTR key seed txt

-- ex 19

bestFit :: ByteString -> Word8
bestFit b = maximumBy (compare `on` score . decode b) [0..255]
  where score = length . filter letter . C.unpack
        decode s c = B.map (xor c) s
        letter x = x `elem` ['a'..'z']++['A'..'Z']++[',','.',' ']

ex19 = do
  r <- lines <$> readFile "../doc/19.txt"
  key <- B.pack . take 16 . randoms <$> newStdGen
  let seed = (0, 0)
      cypher = map (decodeAES128CTR key seed . base64ToByteString) r
      k = B.pack $ map bestFit $ B.transpose cypher
      plain = map (xorB k) cypher
  mapM_ C.putStrLn plain

-- ex 20: Not great results but not great interest in this one. Bestfit method works much better

deXor :: Int64 -> [ByteString] -> (ByteString, ByteString)
deXor k b = (B.concat key, B.concat $ B.transpose msg)
  where (key, msg)  = unzip $ map singleByteXor $ B.transpose b

ex20 = do
  r <- lines <$> readFile "../doc/20.txt"
  key <- B.pack . take 16 . randoms <$> newStdGen
  let seed = (0, 0)
      cypher = map (decodeAES128CTR key seed . base64ToByteString) r
      n = maximum $ map B.length cypher
      cypher' =  map (B.take n) cypher
      (k, plain) = deXor n cypher'
  C.putStrLn plain

-- ex 21

mkSeedMT19937 :: Word32 -> [Word32]
mkSeedMT19937 s0 = drop (fromIntegral n) x
  where x = s ++ zipWith3 comb x (tail x) (drop m x)
        comb x0 x1 xm = let pick i b = b .|. (bit i .&. if i<r then x1 else x0)
                        in xm `xor` twist (foldr pick zeroBits [0..w-1])
        twist b = if testBit b 0 then a `xor` shiftR b 1 else shiftR b 1
        s = s0 : zipWith (\x i -> f*(x `xor` shiftR x (w-2)) +i) s [1..n-1]
        (w, n, m, r) = (32, 624, 397, 31)
        a = 0x9908B0DF
        f = 1812433253

mt19937 :: [Word32] -> (Word32, [Word32])
mt19937 (x:xs) = (temper19937 x, xs)

temper19937 :: Word32 -> Word32
temper19937 = (\y -> xor y (shiftR y l)) . (\y -> xor y (c .&. shiftL y t)) .
              (\y -> xor y (b .&. shiftL y s)) . (\y -> xor y (shiftR y u))
  where
  u = 11
  (s, b) = (7,  0x9D2C5680)
  (t, c) = (15, 0xEFC60000)
  l = 18

-- ex 22

-- ended up not needing this :(
invSeedMT19937 :: Word32 -> [Word32]
invSeedMT19937 sn = s
  where s = sn : zipWith (\x i -> let y=fi*(x-i) in y `xor` shiftR y (w-2)) s [n-1,n-2..1]
        (w, n, m, r) = (32, 624, 397, 31)
        f = 1812433253
        fi = f^0x7FFFFFFF

ex22 = do
  diff <- randomRIO (40, 1000)
  t0 <- fromIntegral . floor <$> getPOSIXTime
  let (r, _) = mt19937 $ mkSeedMT19937 (t0 - diff)
  t1 <- fromIntegral . floor <$> getPOSIXTime
  print $ head $ filter ((r==) . fst . mt19937 . mkSeedMT19937) [t1,t1-1..]


-- ex 23

untemper19937 :: Word32 -> Word32
untemper19937 = inv1 .inv2 . inv3 . inv4
  where
  u = 11
  (s, b) = (7,  0x9D2C5680)
  (t, c) = (15, 0xEFC60000)
  l = 18
  inv1 = (!!3) . iterate (\y -> xor y (shiftR y u))
  inv2 = (!!7) . iterate (\y -> xor y (b .&. shiftL y s))
  inv3 = (\y -> xor y (c .&. shiftL y t))
  inv4 = (\y -> xor y (shiftR y l))

prop_inv1, prop_inv2, prop_inv3, prop_inv4 :: Word32 -> Bool
prop_inv1 x = x == inv1 (f x)
  where f y = xor y (shiftR y 11)
        inv1 = (!!3) . iterate f
prop_inv2 x = x == inv2 (f x)
  where f y = xor y (0x9D2C5680 .&. shiftL y 7)
        inv2 = (!!7) . iterate f
prop_inv3 x = x == inv3 (f x)
  where f y = xor y (0xEFC60000 .&. shiftL y 15)
        inv3 = f
prop_inv4 x = x == inv4 (f x)
  where f y = xor y (shiftR y 18)
        inv4 = f

prop_tempering :: Word32 -> Bool
prop_tempering x = x == untemper19937 (temper19937 x)

prop_twist :: Word32 -> Bool
prop_twist x = x == untwist (twist x)
  where untwist x = if testBit x 31 then shiftL (xor a x) 1 + 1 else shiftL x 1
        twist b = if testBit b 0 then a `xor` shiftR b 1 else shiftR b 1
        a = 0x9908B0DF

-- Misunderstood the question, this should recreate the previous set of seeds
getSeedState :: [Word32] -> [Word32]
getSeedState s = reverse $ take n $ drop n seed
  where seed = s' ++ (recouple $ zipWith combine seed (drop (n-m) seed))
        s' = reverse $ map untemper19937 s
        (w, n, m, r) = (32, 624, 397, 31)
        recouple = zipWith (\(b0, _) (_,b1)  -> b0 + b1) <*> tail
        combine xn xm = let b=untwist (xor xn xm) in (b .&. hBit, b .&. tailBit)
        untwist x = if testBit x 31 then shiftL (xor a x) 1 + 1 else shiftL x 1
        a = 0x9908B0DF
        (hBit, tailBit) = (bit 31, bit 31 - 1)

ex23 = do
  s <- randomIO
  let rnds = take 624 $ unfoldr (Just . mt19937) $ mkSeedMT19937 s
      seedState = map untemper19937 rnds
  print $ seedState == (take 624 $ mkSeedMT19937 s)

-- Ex 24

splitBytes :: Word32 -> [Word8]
splitBytes n = take 4 $ go n ++ repeat 0
  where go 0 = []
        go n = let (q, r) = quotRem n 256 in fromIntegral r : go q


streamEncode :: s -> (s -> (Word32, s)) -> ByteString -> ByteString
streamEncode s g = xorB (B.pack $ concatMap splitBytes $ unfoldr (Just . g) s)

streamDecode = streamEncode

findSeed :: ByteString -> ByteString -> Word32
findSeed plain cypher =  head $ filter check [0..bit 16-1]
  where check s = plain == streamDecode (mkSeedMT19937 s) mt19937 cypher

passwordResetToken :: ByteString -> IO ByteString
passwordResetToken email = do
  t <- fromIntegral . floor <$> getPOSIXTime
  return $ streamEncode (mkSeedMT19937 t) mt19937 $ B.concat ["stuff", email, "more stuff"]

isMT19972TimeSeeded :: (ByteString -> IO ByteString) -> IO Bool
isMT19972TimeSeeded pwdReset = do
  let email = "myemail@email.com"
  token <- pwdReset email
  diff <- randomRIO (40, 1000)
  t <- (+diff) . fromIntegral . floor <$> getPOSIXTime
  let isInfix i = any (B.isPrefixOf i) . B.tails
      goodSeed s = isInfix email $ streamDecode (mkSeedMT19937 s) mt19937 token
  return $ any goodSeed [t,t-1..t-10000]

ex24 = isMT19972TimeSeeded passwordResetToken >>= print
