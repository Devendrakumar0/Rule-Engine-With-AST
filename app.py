from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import operator
import ast
import re

app = Flask(__name__)

# Database Configuration (MySQL with PyMySQL)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:12345@localhost/rule_engine'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Rule model for storing rules
class Rule(db.Model):
    __tablename__ = 'rules'
    id = db.Column(db.Integer, primary_key=True)
    rule_string = db.Column(db.String(500))

    def __repr__(self):
        return f'<Rule {self.id}: {self.rule_string}>'

# AST Node class for building and evaluating rule trees
class ASTNode:
    def __init__(self, type, left=None, right=None, value=None):
        self.type = type  # 'operator' for AND/OR, 'operand' for conditions
        self.left = left  # Left child node
        self.right = right  # Right child node
        self.value = value  # Value for operand nodes

    def __repr__(self):
        return f"ASTNode(type={self.type}, value={self.value})"

# Function to parse the rule string into an AST
def parse_rule_to_ast(rule_string):
    # Replace capitalized logical operators with lowercase equivalents using regex
    normalized_rule = re.sub(r'\bAND\b', 'and', rule_string, flags=re.IGNORECASE)
    normalized_rule = re.sub(r'\bOR\b', 'or', normalized_rule, flags=re.IGNORECASE)
    normalized_rule = re.sub(r'\bNOT\b', 'not', normalized_rule, flags=re.IGNORECASE)

    # Normalize equality operator
    normalized_rule = re.sub(r'(?<![a-zA-Z0-9])=(?!=)', '==', normalized_rule)

    print(f"Normalizing Rule: {normalized_rule}")  # Debug print

    try:
        # Parse the normalized rule string into an AST
        tree = ast.parse(normalized_rule, mode='eval')

        # Ensure the tree is an expression (it should have a 'body' attribute)
        if not isinstance(tree.body, (ast.Expr, ast.BoolOp)):
            raise ValueError("Invalid AST root")
        
        return tree
    except (SyntaxError, ValueError) as e:
        print(f"Error parsing rule: '{rule_string}'\nError: {e}")
        return None


def convert_ast(node):
    if isinstance(node, ast.BoolOp):  # AND / OR operators
        operator = 'AND' if isinstance(node.op, ast.And) else 'OR'
        left = convert_ast(node.values[0])
        right = convert_ast(node.values[1])
        return ASTNode(type='operator', left=left, right=right, value=operator)

    elif isinstance(node, ast.Compare):  # Comparison operators like age > 30
        left = convert_ast(node.left)
        right = convert_ast(node.comparators[0])
        operator = node.ops[0]
        op = '>' if isinstance(operator, ast.Gt) else ('<' if isinstance(operator, ast.Lt) else '==')
        return ASTNode(type='operand', left=left, right=right, value=op)

    elif isinstance(node, ast.Name):  # Variable like age, department
        return ASTNode(type='variable', value=node.id)

    elif isinstance(node, ast.Constant):  # Constant values like 30, 'Sales'
        return ASTNode(type='constant', value=node.value)

    return None


# Function to modify AST nodes (change operators or operands)
def modify_ast(tree, old_operator=None, new_operator=None, old_operand=None, new_operand=None):
    class ModifyVisitor(ast.NodeTransformer):
        def visit_BoolOp(self, node):
            if old_operator and isinstance(node.op, old_operator):
                node.op = new_operator  # Replace operator
            return self.generic_visit(node)

        def visit_Compare(self, node):
            if old_operand and node.left.id == old_operand:
                node.left.id = new_operand  # Replace operand
            return self.generic_visit(node)

    return ModifyVisitor().visit(tree)


def evaluate_ast(ast_root, user_data):
    allowed_operators = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.And: operator.and_,
        ast.Or: operator.or_,
    }

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        elif isinstance(node, ast.BinOp):
            left = _eval(node.left)
            right = _eval(node.right)
            return allowed_operators[type(node.op)](left, right)
        elif isinstance(node, ast.Compare):
            left = _eval(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = _eval(comparator)
                if not allowed_operators[type(op)](left, right):
                    return False
            return True
        elif isinstance(node, ast.BoolOp):
            values = [_eval(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            elif isinstance(node.op, ast.Or):
                return any(values)
        elif isinstance(node, ast.Name):
            if node.id in user_data:
                return user_data[node.id]
            else:
                raise ValueError(f"Undefined variable '{node.id}' in rule")
        elif isinstance(node, ast.Constant):
            return node.value
        else:
            raise ValueError(f"Unsupported AST node type: {type(node)}")

    if isinstance(ast_root, ast.Expression):
        return _eval(ast_root.body)
    elif isinstance(ast_root, ast.BoolOp):
        return _eval(ast_root)
    else:
        raise ValueError("Invalid AST root")

# Home page - Displays form to create a rule and list existing rules
@app.route('/')
def index():
    rules = Rule.query.all()
    return render_template('index.html', rules=rules)

# Endpoint for creating a new rule
@app.route('/create_rule', methods=['POST'])
def create_rule():
    rule_string = request.form['rule_string']
    new_rule = Rule(rule_string=rule_string)
    db.session.add(new_rule)
    db.session.commit()
    return redirect(url_for('index'))

# Endpoint for evaluating a rule against user data
@app.route('/evaluate_rule', methods=['POST'])
def evaluate_rule():
    rule_id = int(request.form['rule_id'])
    rule = Rule.query.get(rule_id)
    
    # User data from the form
    age = int(request.form['age'])
    department = request.form['department']
    salary = int(request.form['salary'])
    experience = int(request.form['experience'])

    user_data = {"age": age, "department": department, "salary": salary, "experience": experience}

    # Parse rule into AST and evaluate
    ast_root = parse_rule_to_ast(rule.rule_string)
    if ast_root is None:
        return "Error parsing rule", 400

    is_eligible = evaluate_ast(ast_root, user_data)

    return render_template('result.html', is_eligible=is_eligible)


# Function to combine two AST nodes with a logical "and" or "or"
def combine_asts(ast1, ast2, operator="or"):
    if operator == "and":
        return ast.BoolOp(op=ast.And(), values=[ast1, ast2])
    elif operator == "or":
        return ast.BoolOp(op=ast.Or(), values=[ast1, ast2])
    else:
        raise ValueError("Unsupported operator for combining rules")

# Main function to combine multiple rules
def combine_rules(rules, operator="or"):
    combined_ast = None
    rules = Rule.query.all()  # Fetch all rules from the database
    for rule in rules:
        # Parse the rule into an AST
        rule_ast = parse_rule_to_ast(rule.rule_string)
        
        if rule_ast is None:
            continue  # Skip invalid rules
        
        # If this is the first rule, initialize the combined AST with it
        if combined_ast is None:
            combined_ast = rule_ast.body  # Use the body of the AST (the expression)
        else:
            # Combine the current AST with the previous one
            combined_ast = combine_asts(combined_ast, rule_ast.body, operator)

    return combined_ast

# Endpoint for editing a rule
@app.route('/edit_rule/<int:rule_id>', methods=['GET', 'POST'])
def edit_rule(rule_id):
    rule = Rule.query.get(rule_id)
    
    if request.method == 'POST':
        # Get the modification details from the form
        new_rule_string = request.form['rule_string']
        rule.rule_string = new_rule_string
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('edit_rule.html', rule=rule)

# Function to update the rule's AST
@app.route('/modify_rule/<int:rule_id>', methods=['POST'])
def modify_rule(rule_id):
    rule = Rule.query.get(rule_id)
    if not rule:
        return "Rule not found", 404

    # Parse the current rule string to AST
    rule_ast = parse_rule_to_ast(rule.rule_string)

    # Example: Replace the operator "and" with "or"
    modified_ast = modify_ast(rule_ast, old_operator=ast.And, new_operator=ast.Or)
    
    # Update the rule string in the database
    rule.rule_string = ast.dump(modified_ast)  # Convert AST back to string
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    rule_id = int(request.form['rule_id'])
    rule = Rule.query.get(rule_id)

    if rule:
        db.session.delete(rule)
        db.session.commit()

    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure database and tables are created
    app.run(debug=True)
