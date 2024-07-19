// Initial Commit: 2024-07-19
// Author: Andrew Wise

### Purpose
The content included here demonstrates C# implementations for either Client Portal Gateway authentication
or through OAuth 1.0a. 
This should not be used as an example of a perfect trading system, but a means of implementing our RESTful 
api with standard C# libraries. 

## Build Details
### C# Build Framework
Both programs were built using C# Target Framework of 6.0.

### NuGet Packages
All packages are pulled from System with the exception of Newtonsoft's JSON library.
Specifically, Newtonsoft.Json by James Newton-King v13.0.3 was used for the original build.

### Note about OAuth Implementation
For users looking to use utilize the OAuth 1.0A implementation, please be aware that you must have a 
funded ORG or Institutional account through Interactive Brokers, with approved access for the OAuth 
self-service portal, provided by the IBKR API Support team for qualified accounts..