{-# LANGUAGE OverloadedStrings #-}

module Set5 (expMod, p, mix, generateParam, encrypt, decrypt) where

import           Encodings
import           AES128
import           Hashes
import           System.Random
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C
import           Data.Map (Map, (!))
import qualified Data.Map as M

byteStringToInt :: (Integral a) => ByteString -> a
byteStringToInt = B.foldl' (\n w -> 256 * n + fromIntegral w) 0

expMod :: (Integral a) => a -> a -> a -> a
expMod _ _ 1 = 0
expMod b p m = go 1 (mod b m) p
  where go res base expo
          | expo <= 0 = res
          | otherwise = go res' (mod (base^2) m) (div expo 2)
          where res' = if mod expo 2 == 1 then mod (res * base) m else res

p :: Integer
p = read $ concat ["0x",
              "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024",
              "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd",
              "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec",
              "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f",
              "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361",
              "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552",
              "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff",
              "fffffffffffff"]

mix :: (Integral a) => a -> a -> a -> a
mix n p g = expMod g n p

ex33 = sab == sba
  where a = 134452225454353
        b = 865984353645522
        g = 2
        sa = mix a p g
        sb = mix b p g
        sab = mix a p sb
        sba = mix b p sa

generateParam :: IO (Integer, Integer, Integer)
generateParam = do
  (p', gen) <- randomR (1, p) <$> newStdGen
  let (a, gen') = randomR (1, p') gen
      (g, _) = randomR (1, p') gen'
  return (a, p', g)

encrypt :: Integer -> ByteString -> IO ByteString
encrypt s msg = do
  let key = B.take 16 $ sha1 $ intToByteString s
  iv <- B.pack . take 16 . randoms <$> newStdGen
  return $ B.append iv $ encodeAES128CBC key iv msg

decrypt :: Integer -> ByteString -> ByteString
decrypt s full =
  let key = B.take 16 $ sha1 $ intToByteString s
      (iv, encr) = B.splitAt 16 full
  in decodeAES128CBC key iv encr

ex34' = do -- Simple protocol
  -- A->M: Send "p", "g", "A"
  (a, p , g) <- generateParam
  let sa = mix a p g
  -- B -> A: Send "B"
  (b, _ , _) <- generateParam
  let sb = mix b p g
      s = mix b p sa
  -- A -> B: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  msgA <- encrypt s "Hello B, how are you?"
  -- B -> A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  let decryptedA = decrypt s msgA
  print decryptedA
  msgB <- encrypt s decryptedA
  -- A decrypts
  let decryptedB = decrypt s msgB
  print decryptedB

ex34 = do -- Man in the middle attack
      -- A->M: Send "p", "g", "A"
  (a, p , g) <- generateParam
  let sa = mix a p g
      -- M->B: Send "p", "g", "p"
      -- B->M: Send "B"
  (b, _ , _) <- generateParam
  let sb = mix b p g
      sForB = mix b p p -- p instead of sa ==> sForB == 0
      -- M->A: Send "p"
      -- A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  let sForA = mix a p p -- p instead of sb ==> sForA == 0
  msgA <- encrypt sForA "Hello B, how are you?"
      -- M->B: Relay that to B
      -- B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  let decryptedA = decrypt sForB msgA
  print decryptedA
  msgB <- encrypt sForB decryptedA
      -- M->A: Relay that to A, A decrypts
  let decryptedB = decrypt sForA msgB
  print decryptedB


ex35a = do -- Man in the middle attack
      -- A->M: Send "p", "g"
  (a, p , g') <- generateParam
      -- M: Renegociate p, g=1
  let g = 1
      sa = mix a p g
  (b, _ , _) <- generateParam
  let sb = mix b p g
      sForB = mix b p sa
      -- M->A: Send "p"
      -- A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  let sForA = mix a p sb
  msgA <- encrypt sForA "Hello B, how are you?"
      -- M->B: Relay that to B
      -- B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  let decryptedA = decrypt sForB msgA
  print decryptedA
  msgB <- encrypt sForB decryptedA
      -- M->A: Relay that to A, A decrypts
  let decryptedB = decrypt sForA msgB
  print decryptedB

ex35b = do -- Man in the middle attack
      -- A->M: Send "p", "g"
  (a, p , g') <- generateParam
      -- M: Renegociate p, g=1
  let g = p
      sa = mix a p g
  (b, _ , _) <- generateParam
  let sb = mix b p g
      sForB = mix b p sa
      -- M->A: Send "p"
      -- A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  let sForA = mix a p sb
  msgA <- encrypt sForA "Hello B, how are you?"
      -- M->B: Relay that to B
      -- B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  let decryptedA = decrypt sForB msgA
  print decryptedA
  msgB <- encrypt sForB decryptedA
      -- M->A: Relay that to A, A decrypts
  let decryptedB = decrypt sForA msgB
  print decryptedB

ex35c = do -- Man in the middle attack
      -- A->M: Send "p", "g"
  (a, p , g') <- generateParam
      -- M: Renegociate p, g=1
  let g = p-1
      sa = mix a p g -- even a => sa = 1, odd a => sa = p-1
  (b, _ , _) <- generateParam
  let sb = mix b p g -- even b => sb = 1, odd b => sb = p-1
      sForB = mix b p sa -- sa=1 => sForB=1, sa=p-1 => sForB=sb
      -- M->A: Send "p"
      -- A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  let sForA = mix a p sb -- sb=1 => sForA=1, sa=p-1 => sForA=sa
  msgA <- encrypt sForA "Hello B, how are you?"
      -- M->B: Relay that to B
      -- B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  let decryptedA = decrypt sForB msgA
  print decryptedA
  msgB <- encrypt sForB decryptedA
      -- M->A: Relay that to A, A decrypts
  let decryptedB = decrypt sForA msgB
  print decryptedB

ex36 = do
  -- C & S agree on constants
  let n = p
      g = 2
      k = 3
      email = "jie@mail.com"
      password = "super secret"
  -- S: salt, v
  salt <- randomIO :: IO Integer
  let xH = sha256 $ B.append (intToByteString salt) password
      x = read $ "0x" ++ (byteStringToHex xH) :: Integer
      v = expMod g x n
  -- C->S: Send I, A=g**a % N (a la Diffie Hellman)
  (a, _, _) <- generateParam
  let sa = expMod g a n
  -- S->C: Send salt, B=kv + g**b % N
  (b, _, _) <- generateParam
  let sb = k * v + expMod g b n
  -- S, C: Compute string uH = SHA256(A|B), u = integer of uH
      uH = sha256 (B.append (intToByteString sa) (intToByteString sb))
      u = read $ "0x" ++ (byteStringToHex uH) :: Integer
  -- C
      -- xH = ...
      -- x = ...
      sForA = expMod (sb - k * expMod g x n) (a + u * x) n
      ka = sha256 (intToByteString sForA)
  -- S
      sForB = expMod (sa * expMod v u n) b n
      kb = sha256 (intToByteString sForB)
  -- C->S: Send HMAC-SHA256(K, salt)
      msgA = hMAC sha256 64 ka (intToByteString salt)
  -- S->C: Send "OK" if HMAC-SHA256(K, salt) validates
  if msgA == hMAC sha256 64 kb (intToByteString salt)
    then print "OK"
    else print "Not OK"
