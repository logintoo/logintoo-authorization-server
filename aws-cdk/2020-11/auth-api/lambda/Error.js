class ValidationError extends Error {
  constructor(message, instance) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = 400;

    if (typeof instance == 'object') {
      this.instance = instance;
    }
  }
}

class DatabaseError extends Error {
  constructor(message, dbError) {
    super(message);
    this.name = 'DatabaseError';

    if (typeof dbError == 'object') {
      this.retryable = dbError.retryable;
      this.statusCode = dbError.statusCode;
      this.dbError = dbError;
    }
  }
}

class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotFoundError';
    this.statusCode = 403;
  }
}

class UnauthorizedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnauthorizedError';
    this.statusCode = 401;
  }
}

module.exports = { ValidationError, DatabaseError, NotFoundError, UnauthorizedError };
