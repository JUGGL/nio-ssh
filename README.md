# nio-ssh

## Current Status
1 - Not functional yet

## Overview

This library is a pure Java implementation of the SSH protocol (both client and server). There are several differences
between this implementation and other available Java implementations of SSH.

* This project relies on the [Bouncy Castle](http://www.bouncycastle.org/) cryptography library to handle almost all crypto operations (Hashes, ciphers, etc...).
* This project uses NIO Channels and Selectors to allow for asynchronous networking so that it can be used with reactive applications.
* All code in this project is intended to have clear and simple to understand documentation so that you need not be an expert in cryptography to understand it's use.
* Excellent Unit Test coverage will be the norm

Using an external crypto library has the benefit that this project will never need to worry about falling behind the
latest crypto updates. That work is left to the creators and maintainers of the Bouncy Castle library, and that is their
area of expertise and passion.

Using NIO for socket programming means that a minimal number of threads can be used to support multitudes of SSH sessions.

By having clear and concise documentation (including JavaDoc on all methods, even private ones) we hope to make this
library simple to understand and to implement.

By having extremely high unit test coverage, we can ensure that as the libraries this project depends on evolve, it will
be trivial to detect when those libraries have sufficiently diverged as to cause problems in this software. Also, test 
coverage will help us to ensure that we will not have regressions and can always assure consistent operation.

## Contributing

As the maintainer of this project, I will require extensive unit tests for any code which is to be merged into this 
project. It is also my intent to design unit tests to reproduce any issues which will need to be resolved as they are 
identified. If an issue is identified and it passes all current tests, then adding a test to reproduce the issue will be
paramount to ensuring that the same issue does not re-appear in the future.

Now, that said, contributions without unit tests may eventually get merged. The process for getting those changes into
the released code will require someone to write tests, verify the documentation, and ensure that the project style is
conformed with.

### Coding Guidelines
* 4 space indentation
* K&R style braces (Braces on the same line as the expression which starts the block of code)

```java
if (name="Correct") {
   System.out.println("Correct!");
}

if (name="Incorrect")
{
    System.out.println("Incorrect!!");
}
```
* Maximum line length SHOULD be 120 characters where possible. This is not an absolute rule and will be judged by readability.
* No [Magic Numbers](http://en.wikipedia.org/wiki/Magic_number_%28programming%29). Magic Numbers refers to "Unique values with unexplained meaning or multiple occurrences which could (preferably) be replaced with named constants"

```java
// Not Acceptable

byte[] packet = in.readBytes(5);

// Preferred

/**
 * The length of the packet header
 */
private static final int HEADER_LENGTH = 5;

byte[] packet = in.readBytes(HEADER_LENGTH);
```
* All methods MUST have descriptive JavaDoc comments which cover all return values, input parameters, and exceptions thrown. Even private/protected methods must be documented.
* Unbounded Exception SHOULD be avoided.

```java
public void myMethod() thows Exception { ... }   // Incorrect

public void myMethod() throws IOException, SecurityException { ... }  // Correct
```
* Remember the "Next Guy Principal"... All of the code included in this project will be maintained by many people and used by many more, so the code you write should be comprehensible by high school students.
* The project will be managed using [Apache Maven](http://maven.apache.org/) until such time that another build tool is determined to be a better alternative
* All source files should be prefaced with a License header reflecting the license for this project (Apache License). An example is shown below:

```
Copyright [yyyy] [Your Name]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
* API design should learn lessons from other SPIs which are intended to be [long-lived and evolve](http://blog.jooq.org/2015/05/21/do-not-make-this-mistake-when-developing-an-spi/).
* Contributors to this project retain all copyrights to their work. If, at a future date, a license change is desirable; all contributors MUST agree or their code must be rewritten as a "clean-room" implementation.
* Others as they are identified and codified

### Project Organization
* As more people join this project and contribute, a maintainers council will be formed.
  * This is intended to avoid having a [BDFL](http://en.wikipedia.org/wiki/Benevolent_dictator_for_life). 
* Each member of the council will have a vote for the direction of the project 
* It is intended that users will also be able to vote on priorities for new features and bug fixes
* All contributors are expected to be civil to other maintainers as well as to users
  * I recall my early years as a developer and the disdain and contempt which was heaped upon me, I would be very disappointed if a project I started behaved the same way.
