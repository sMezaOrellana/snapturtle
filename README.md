
# Snapturtle an Endpoint Security Client

## Overview

This project demonstrates the use of Apple's Endpoint Security (ES) framework to handle security-related events on macOS. It includes functionalities for subscribing to events, handling authentication requests, and logging event details.
Very much a POC.

Inspired by the implementation of Omar Ikram
https://gist.github.com/Omar-Ikram/8e6721d8e83a3da69b31d4c2612a68ba#file-endpointsecuritydemo-m

## Status
Currently only 2 events are logged (ES_AUTH_OPEN, ES_AUTH_EXEC). Output is redirected to a `./logs` file. 

## Setup

1. **Clone the Repository:**
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   make
   ./snapturtle
   ```

