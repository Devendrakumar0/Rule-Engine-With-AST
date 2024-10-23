# Rule-Engine-With-AST
## Overview
This project implements a Rule Engine that dynamically creates, modifies, and evaluates user rules using Abstract Syntax Tree (AST) in Python Flask. The system allows users to input rules for attributes like age, department, salary, and experience and evaluates them based on user-provided data.

## Features
- Create and modify rules.
- Evaluate rules based on user input.
- AST-based evaluation for flexibility.
- Supports complex logical operations (`AND`, `OR`).

## Build Instructions

### Prerequisites
- Python 3.x
- MySQL
### Installation commands
- pip install Flask
- pip install SQLAlchemy

## Database Setup
### Set up MySQL (or another database you're using) and create the necessary tables:

- sql

**CREATE DATABASE rule_engine;
USE rule_engine;**

- Example table for rules
**CREATE TABLE rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_string VARCHAR(255) NOT NULL
);**



## After setup
### run the command
python app.py

  
