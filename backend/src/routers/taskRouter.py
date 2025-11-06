from flask import Blueprint, request, jsonify

from controllers.controllers import *

taskRouter = Blueprint('taskRouter', __name__)





@taskRouter.post('/api/task/', strict_slashes=False)
def handle_scan_request():
    return handle_url()

