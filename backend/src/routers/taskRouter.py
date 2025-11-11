from flask import Blueprint, request, jsonify

from controllers.mainapi import *

taskRouter = Blueprint('taskRouter', __name__)





@taskRouter.post('/api/task/', strict_slashes=False)
def handle_url():
    return handle_scan_request()

