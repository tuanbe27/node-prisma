import { readFileSync } from 'fs';

import config from 'config';
import { SignOptions, verify, sign } from 'jsonwebtoken';

import { TokenType } from '../types';

// Sign Token
export const signJwt = (
  payload: object,
  keyName: TokenType,
  options: SignOptions
): string => {
  const privateKey = Buffer.from(
    config.get<string>(keyName),
    'base64'
  ).toString('ascii');

  // Read the private key from a file
  const test = readFileSync('public_key.pem', 'utf8');
  const buff = Buffer.from(test).toString('base64');
  console.log(buff);

  return sign(payload, privateKey, {
    ...(options && options),
    algorithm: 'RS256',
  });
};

// Verify Token
export const verifyJwt = <T>(token: string, keyname: TokenType): T | null => {
  try {
    const publicKey = Buffer.from(
      config.get<string>(String(keyname)),
      'base64'
    ).toString('ascii');

    const decode = verify(token, publicKey) as T;

    return decode;
  } catch (error) {
    console.log('error when verifyJwt', error);
    return null;
  }
};
