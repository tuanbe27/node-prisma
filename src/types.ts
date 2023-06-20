export enum TokenType {
  ACCESS_TOKEN_PUBLIC = 'accessTokenPublicKey',
  ACCESS_TOKEN_PRIVATE = 'accessTokenPrivateKey',
  REFRESH_TOKEN_PUBLIC = 'refreshTokenPublicKey',
  REFRESH_TOKEN_PRIVATE = 'refreshTokenPrivateKey',
}

export enum DefaultErrorMessage {
  BadRequest = 'Oops! The request was not valid.',
  Unauthorized = 'Oops! You are not authorized to access this resource.',
  Forbidden = "Oops! You don't have permission to access this resource.",
  NotFound = 'Oops! The requested page was not found.',
  InternalServerError = 'Oops! Something went wrong on our end. Please try again later.',
  PaymentRequired = 'Oops! Payment is required to proceed.',
  MethodNotAllowed = 'Oops! The requested method is not allowed for this resource.',
  NotAcceptable = 'Oops! The requested content is not acceptable.',
}
