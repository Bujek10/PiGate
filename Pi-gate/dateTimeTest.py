from flask import Flask, render_template, Response, request
import cv2


camera = cv2.VideoCapture(0)

def gen_frames():  # generate frame by frame from camera
    while True:
        success, frame = camera.read()
        if success:
            try:
                ret, buffer = cv2.imencode('.jpg', cv2.flip(frame, 1))
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                    b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            except Exception:
                pass
        else:
            pass


@app.route('/video_feed')
@login_required
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

