# Technologies

- [Node.js](https://nodejs.org/en) – a Javascript run-time language built on
  Google’s V8 engine
- [Prisma](https://www.prisma.io/) – an ORM(Object Relational Mapping) that
  supports some of the popular databases (PostgreSQL, MySQL, SQLite, etc). Also,
  at the time of writing this article, it only supports Javascript and
  Typescript.
- [PostgreSQL](https://www.postgresql.org/) – an object-relational database
  system
- [JsonWebToken](https://jwt.io/) – for generating and verifying JSON Web Tokens
- [Redis](https://redis.io/) – an in-memory data structure store used as a
  database

# Authentication route

- Register a new account
- Login with the registered credentials
- Refresh the access token when expired
- Retrieve his profile information only if logged in.

| RESOURCE | HTTP METHOD | ROUTE              | DESCRIPTION                      |
| -------- | ----------- | ------------------ | -------------------------------- |
| users    | GET         | /api/users/me      | Retrieve user’s information      |
| auth     | POST        | /api/auth/register | Register new user                |
| auth     | POST        | /api/auth/login    | Login registered user            |
| auth     | GET         | /api/auth/refresh  | Refresh the expired access token |
| auth     | GET         | /api/auth/logout   | Logout the user                  |

## User Login and Register Flow with JWT Authentication

- The diagram below illustrates the user registration flow in the Node.js app.

  ![User-registration-flow-with-email-verification](https://i.imgur.com/3p7Z9TX.jpg)

- The diagram below illustrates JWT authentication flow in the Node.js app.

  ![Jwt-Authentication-flow-with-React-and-backend-api](https://i.imgur.com/TyjpuXk.jpg)

- Below is a summary of how the access token will be refreshed:

  ![Refresh-Access-Token-Flow-JWT-Authentication](https://i.imgur.com/dcQ5uSG.jpg)

  - First, the browser sends the cookies along with any request to the server

  - The server then checks if the access token was included in the request
    before validating it. An error is sent if the token has expired or was
    manipulated.

  - The frontend application receives the unauthorized error and uses
    interceptors to refresh the access token.

  - In brief, the frontend app will make a GET request to `/api/auth/refresh` to
    get a new access token cookie before re-trying the previous request.
