from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_session import Session
from flask_mail import Mail, Message
from flask_mysqldb import MySQL
import math, random 
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, DateTimeField, BooleanField, IntegerField, DecimalField, HiddenField, SelectField, RadioField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms_components import TimeField
from wtforms.fields import DateField
from wtforms.validators import ValidationError, NumberRange
from datetime import timedelta, datetime
from coolname import generate_slug
from werkzeug.utils import secure_filename
import pandas as pd
import stripe
import operator
import functools
import math, random 
import csv
# import cv2
import numpy as np
import json
import base64
from flask_session import Session
from flask_cors import CORS, cross_origin

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'ksheeraj'
app.config['MYSQL_PORT'] = 3308
app.config['MYSQL_PASSWORD'] = 'Datta@2003'
app.config['MYSQL_DB'] = 'project'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['MAIL_SERVER']='smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'datta.ksheeraj@gmail.com'
app.config['MAIL_PASSWORD'] = 'mdby qcvt pvcb ianh'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mysql = MySQL(app)
mail = Mail(app)


app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'secret_key'

sender = 'datta.ksheeraj@gmail.com'
sess = Session()
sess.init_app(app)

@app.before_request
def make_session_permanent():
	session.permanent = True

def user_role_professor(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			if session['user_role']=="teacher":
				return f(*args, **kwargs)
			else:
				flash('You dont have privilege to access this page!','danger')
				return render_template("404.html") 
		else:
			flash('Unauthorized, Please login!','danger')
			return redirect(url_for('login'))
	return wrap

def user_role_student(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			if session['user_role']=="student":
				return f(*args, **kwargs)
			else:
				flash('You dont have privilege to access this page!','danger')
				return render_template("404.html") 
		else:
			flash('Unauthorized, Please login!','danger')
			return redirect(url_for('login'))
	return wrap


@app.route('/')
def index():
    return render_template('index.html')

def generateOTP() : 
    digits = "0123456789"
    OTP = "" 
    for i in range(5) : 
        OTP += digits[math.floor(random.random() * 10)] 
    return OTP 

@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		email = request.form['email']
		password_candidate = request.form['password']
		user_type = request.form['user_type']
		cur = mysql.connection.cursor()
		results1 = cur.execute('SELECT uid, name, email, password, user_type from users where email = %s and user_type = %s and user_login = 0' , (email,user_type))
		if results1 > 0:
			cresults = cur.fetchone()
			password = cresults['password']
			name = cresults['name']
			uid = cresults['uid']
			if password == password_candidate:
				results2 = cur.execute('UPDATE users set user_login = 1 where email = %s' , [email])
				mysql.connection.commit()
				if results2 > 0:
					session['logged_in'] = True
					session['email'] = email
					session['name'] = name
					session['user_role'] = user_type
					session['uid'] = uid
					if user_type == "student":
						return redirect(url_for('student_index'))
					else:
						return redirect(url_for('professor_index'))
				else:
					error = 'Error Occurred!'
					return render_template('login.html', error=error)	
			else:
				error = 'You have entered Invalid password or Already login'
				return render_template('login.html', error=error)
			cur.close()
		else:
			error = 'Already Login or Email was not found!'
			return render_template('login.html', error=error)
	return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
	if request.method == 'POST':
		name = request.form['name']
		email = request.form['email']
		password = request.form['password']
		user_type = request.form['user_type']
		session['tempName'] = name
		session['tempEmail'] = email
		session['tempPassword'] = password
		session['tempUT'] = user_type
		sesOTP = generateOTP()
		session['tempOTP'] = sesOTP
		msg1 = Message('MyProctor.ai - OTP Verification', sender = sender, recipients = [email])
		msg1.body = "New Account opening - Your OTP Verfication code is "+sesOTP+"."
		mail.send(msg1)
		return redirect(url_for('verifyEmail')) 
	return render_template('register.html')

@app.route('/verifyEmail', methods=['GET','POST'])
def verifyEmail():
	if request.method == 'POST':
		theOTP = request.form['eotp']
		mOTP = session['tempOTP']
		dbName = session['tempName']
		dbEmail = session['tempEmail']
		dbPassword = session['tempPassword']
		dbUser_type = session['tempUT']
		if(theOTP == mOTP):
			cur = mysql.connection.cursor()
			ar = cur.execute('INSERT INTO users(name, email, password, user_type, user_login) values(%s,%s,%s,%s,%s)', (dbName, dbEmail, dbPassword, dbUser_type, 0))
			mysql.connection.commit()
			if ar > 0:
				flash("Thanks for registering! You are sucessfully verified!.")
				return  redirect(url_for('login'))
			else:
				flash("Error Occurred!")
				return  redirect(url_for('login')) 
			cur.close()
			session.clear()
		else:
			return render_template('register.html',error="OTP is incorrect.")
	return render_template('verifyEmail.html')

@app.route('/student_index')
@user_role_student
def student_index():
	return render_template('student_index.html')

@app.route('/professor_index')
@user_role_professor
def professor_index():
	return render_template('professor_index.html')

@app.route('/logout', methods=["GET", "POST"])
def logout():
	cur = mysql.connection.cursor()
	lbr = cur.execute('UPDATE users set user_login = 0 where email = %s and uid = %s',(session['email'],session['uid']))
	mysql.connection.commit()
	if lbr > 0:
		session.clear()
		return "success"
	else:
		return "error"

class UploadForm(FlaskForm):
	subject = StringField('Subject')
	topic = StringField('Topic')
	doc = FileField('CSV Upload', validators=[FileRequired()])
	start_date = DateField('Start Date')
	start_time = TimeField('Start Time', default=datetime.utcnow()+timedelta(hours=5.5))
	end_date = DateField('End Date')
	end_time = TimeField('End Time', default=datetime.utcnow()+timedelta(hours=5.5))
	calc = BooleanField('Enable Calculator')
	neg_mark = DecimalField('Enable negative marking in % ', validators=[NumberRange(min=0, max=100)])
	duration = IntegerField('Duration(in min)')
	password = PasswordField('Exam Password', [validators.Length(min=3, max=6)])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")
	
	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")
	
	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

class TestForm(Form):
	test_id = StringField('Exam ID')
	password = PasswordField('Exam Password')
	img_hidden_form = HiddenField(label=(''))


@app.route('/create-test', methods = ['GET', 'POST'])
@user_role_professor
def create_test():
	form = UploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		test_id = generate_slug(2)
		filename = secure_filename(form.doc.data.filename)
		filestream = form.doc.data
		filestream.seek(0)
		ef = pd.read_csv(filestream)
		fields = ['qid','q','a','b','c','d','ans','marks']
		df = pd.DataFrame(ef, columns = fields)
		cur = mysql.connection.cursor()
		for row in df.index:
			cur.execute('INSERT INTO questions(test_id,qid,q,a,b,c,d,ans,marks,uid) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (test_id, df['qid'][row], df['q'][row], df['a'][row], df['b'][row], df['c'][row], df['d'][row], df['ans'][row], df['marks'][row], session['uid']))
			cur.connection.commit()

		start_date = form.start_date.data
		end_date = form.end_date.data
		start_time = form.start_time.data
		end_time = form.end_time.data
		start_date_time = str(start_date) + " " + str(start_time)
		end_date_time = str(end_date) + " " + str(end_time)
		neg_mark = int(form.neg_mark.data)
		calc = int(form.calc.data)
		duration = int(form.duration.data)*60
		password = form.password.data
		subject = form.subject.data
		topic = form.topic.data
		cur.execute('INSERT INTO teachers (email, test_id, test_type, start, end, duration, show_ans, password, subject, topic, neg_marks, calc, uid) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
			(dict(session)['email'], test_id, "objective", start_date_time, end_date_time, duration, 1, password, subject, topic, neg_mark, calc, session['uid']))
		mysql.connection.commit()
		cur.close()
		flash(f'Exam ID: {test_id}', 'success')
		return redirect(url_for('professor_index'))
		
	return render_template('create_test.html' , form = form)

@app.route('/viewquestions', methods=['GET'])
@user_role_professor
def viewquestions():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where email = %s and uid = %s', (session['email'],session['uid']))
	if results > 0:
		cresults = cur.fetchall()
		cur.close()
		return render_template("viewquestions.html", cresults = cresults)
	else:
		return render_template("viewquestions.html", cresults = None)

@app.route('/displayquestions', methods=['GET','POST'])
@user_role_professor
def displayquestions():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT * from questions where test_id = %s and uid = %s', (tidoption,session['uid']))
		callresults = cur.fetchall()
		cur.close()
		return render_template("displayquestions.html", callresults = callresults)
				
@app.route("/give-test", methods = ['GET', 'POST'])
@user_role_student
def give_test():
	global duration, marked_ans, calc, subject, topic
	form = TestForm(request.form)
	if request.method == 'POST' and form.validate():
		
		test_id = form.test_id.data
		password_candidate = form.password.data
		results1 = 1
		if results1 > 0:
			print("ghghgh")
			cur = mysql.connection.cursor()
			results = cur.execute('SELECT * from teachers where test_id = %s', [test_id])
			if results > 0:
				print("noooo")
				data = cur.fetchone()
				password = data['password']
				duration = data['duration']
				calc = data['calc']
				subject = data['subject']
				topic = data['topic']
				start = data['start']
				start = str(start)
				end = data['end']
				end = str(end)
				if password == password_candidate:
					print("dattta")
					now = datetime.now()
					now = now.strftime("%Y-%m-%d %H:%M:%S")
					now = datetime.strptime(now,"%Y-%m-%d %H:%M:%S")
					if datetime.strptime(start,"%Y-%m-%d %H:%M:%S") < now and datetime.strptime(end,"%Y-%m-%d %H:%M:%S") > now:
						print("kesheeraj")
						results = cur.execute('SELECT time_to_sec(time_left) as time_left,completed from studenttestinfo where email = %s and test_id = %s', (session['email'], test_id))
						if results > 0:
							print("ffhhh")
							results = cur.fetchone()
							is_completed = results['completed']
							if is_completed == 0:
								print("manu")
								time_left = results['time_left']
								if time_left <= duration:
									print("qwrty")
									duration = time_left
									results = cur.execute('SELECT qid , ans from students where email = %s and test_id = %s and uid = %s', (session['email'], test_id, session['uid']))
									marked_ans = {}
									if results > 0:
										print("jjjj")
										results = cur.fetchall()
										for row in results:
											print(row['qid'])
											qiddb = ""+row['qid']
											print(qiddb)
											marked_ans[qiddb] = row['ans']
											marked_ans = json.dumps(marked_ans)
							else:
								print("hello")
								flash('Exam already given', 'success')
								return redirect(url_for('give_test'))
						else:
							print("woprr")
							cur.execute('INSERT into studenttestinfo (email, test_id,time_left,uid) values(%s,%s,SEC_TO_TIME(%s),%s)', (session['email'], test_id, duration, session['uid']))
							mysql.connection.commit()
							results = cur.execute('SELECT time_to_sec(time_left) as time_left,completed from studenttestinfo where email = %s and test_id = %s and uid = %s', (session['email'], test_id, session['uid']))
							if results > 0:
								results = cur.fetchone()
								is_completed = results['completed']
								if is_completed == 0:
									time_left = results['time_left']
									if time_left <= duration:
										duration = time_left
										results = cur.execute('SELECT * from students where email = %s and test_id = %s and uid = %s', (session['email'], test_id, session['uid']))
										marked_ans = {}
										if results > 0:
											results = cur.fetchall()
											for row in results:
												marked_ans[row['qid']] = row['ans']
											marked_ans = json.dumps(marked_ans)
					else:
						if datetime.strptime(start,"%Y-%m-%d %H:%M:%S") > now:
							print("hello1")
							flash(f'Exam start time is {start}', 'danger')
						else:
							print("hello2")
							flash(f'Exam has ended', 'danger')
						return redirect(url_for('give_test'))
					return redirect(url_for('test' , testid = test_id))
					print("raavali")
				else:
					print("hello3")
					flash('Invalid password', 'danger')
					return redirect(url_for('give_test'))
			print("hello4")
			flash('Invalid testid', 'danger')
			return redirect(url_for('give_test'))
			cur.close()
	return render_template('give_test.html', form = form)

@app.route('/give-test/<testid>', methods=['GET','POST'])
@user_role_student
def test(testid):
	cur = mysql.connection.cursor()
	cur.close()

	global duration, marked_ans, calc, subject, topic
	if request.method == 'GET':
		print("HELLO")
		try:
			data = {'duration': duration, 'marks': '', 'q': '', 'a': '', 'b':'','c':'','d':'' }
			return render_template('testquiz.html' ,**data, answers=marked_ans, calc=calc, subject=subject, topic=topic, tid=testid)
		except:
			
			return redirect(url_for('give_test'))
	else:
		cur = mysql.connection.cursor()
		flag = request.form['flag']
		for key, value in request.form.items():
			print(f'{key}: {value}')
		if flag == 'get':
			num = request.form['no']
			print(num)
			results = cur.execute('SELECT test_id,qid,q,a,b,c,d,ans,marks from questions where test_id = %s and qid =%s',(testid, num))
			if results > 0:
				print("hhehe")
				data = cur.fetchone()
				print(data)
				del data['ans']
				cur.close()
				return json.dumps(data)
			else:
				print("hello")
				return json.dumps({'error':'error'})
		elif flag=='mark1':
			print("marlk")
			qid = request.form['qid']
			ans = request.form['ans']
			# print(ans)
			print(qid)
			cur = mysql.connection.cursor()
			results = cur.execute('SELECT * from students where test_id =%s and qid = %s and email = %s', (testid, qid, session['email']))
			if results > 0:
				cur.execute('UPDATE students set ans = %s where test_id = %s and qid = %s and email = %s', (testid, qid, session['email']))
				mysql.connection.commit()
				cur.close()
			else:
				cur.execute('INSERT INTO students(email,test_id,qid,ans,uid) values(%s,%s,%s,%s,%s)', (session['email'], testid, qid, ans, session['uid']))
				mysql.connection.commit()
				cur.close()
		elif flag=='time':
			print("time")
			cur = mysql.connection.cursor()
			time_left = request.form['time']
			try:
				cur.execute('UPDATE studenttestinfo set time_left=SEC_TO_TIME(%s) where test_id = %s and email = %s and uid = %s and completed=0', (time_left, testid, session['email'], session['uid']))
				mysql.connection.commit()
				cur.close()
				return json.dumps({'time':'fired'})
			except:
				pass
		else:
			print("ffff")
			cur = mysql.connection.cursor()
			cur.execute('UPDATE studenttestinfo set completed=1,time_left=sec_to_time(0) where test_id = %s and email = %s and uid = %s', (testid, session['email'],session['uid']))
			mysql.connection.commit()
			cur.close()
			flash("Exam submitted successfully", 'info')
			return json.dumps({'sql':'fired'})

@app.route('/randomize', methods = ['POST'])
def random_gen():
	if request.method == "POST":
		id = request.form['id']
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT count(*) from questions where test_id = %s', [id])
		if results > 0:
			data = cur.fetchone()
			total = data['count(*)']
			nos = list(range(1,int(total)+1))
			random.Random(id).shuffle(nos)
			cur.close()
			return json.dumps(nos)

@app.route('/window_event', methods=['GET','POST'])
@user_role_student
def window_event():
	if request.method == "POST":
		testid = request.form['testid']
		cur = mysql.connection.cursor()
		results = cur.execute('INSERT INTO window_estimation_log (email, test_id, name, window_event, uid) values(%s,%s,%s,%s,%s)', (dict(session)['email'], testid, dict(session)['name'], 1, dict(session)['uid']))
		mysql.connection.commit()
		cur.close()
		if(results > 0):
			return "recorded window"
		else:
			return "error in window"

@app.route('/<email>/<testid>')
@user_role_student
def check_result(email, testid):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * FROM teachers where test_id = %s', [testid])
		if results>0:
			results = cur.fetchone()
			check = results['show_ans']
			if check == 1:
				results = cur.execute('select q,a,b,c,d,marks,q.qid as qid, \
					q.ans as correct, ifnull(s.ans,0) as marked from questions q left join \
					students s on  s.test_id = q.test_id and s.test_id = %s \
					and s.email = %s and s.uid = %s and s.qid = q.qid group by q.qid \
					order by LPAD(lower(q.qid),10,0) asc', (testid, email, session['uid']))
				if results > 0:
					results = cur.fetchall()
					return render_template('tests_result.html', results= results)
			else:
				flash('You are not authorized to check the result', 'danger')
				return redirect(url_for('tests_given',email = email))
	else:
		return redirect(url_for('student_index'))

def neg_marks(email,testid,negm):
	cur=mysql.connection.cursor()
	results = cur.execute("select marks,q.qid as qid, \
				q.ans as correct, ifnull(s.ans,0) as marked from questions q inner join \
				students s on  s.test_id = q.test_id and s.test_id = %s \
				and s.email = %s and s.qid = q.qid group by q.qid \
				order by q.qid asc", (testid, email))
	data=cur.fetchall()

	sum=0.0
	for i in range(results):
		if(str(data[i]['marked']).upper() != '0'):
			if(str(data[i]['marked']).upper() != str(data[i]['correct']).upper()):
				sum=sum - (negm/100) * int(data[i]['marks'])
			elif(str(data[i]['marked']).upper() == str(data[i]['correct']).upper()):
				sum+=int(data[i]['marks'])
	return sum

def totmarks(email,tests): 
	cur = mysql.connection.cursor()
	for test in tests:
		testid = test['test_id']
		results=cur.execute("select neg_marks from teachers where test_id=%s",[testid])
		results=cur.fetchone()
		negm = results['neg_marks']
		data = neg_marks(email,testid,negm)
		return data

def marks_calc(email,testid):
		cur = mysql.connection.cursor()
		results=cur.execute("select neg_marks from teachers where test_id=%s",[testid])
		results=cur.fetchone()
		negm = results['neg_marks']
		return neg_marks(email,testid,negm) 
		
@app.route('/<email>/tests-given', methods = ['POST','GET'])
@user_role_student
def tests_given(email):
	if request.method == "GET":
		if email == session['email']:
			cur = mysql.connection.cursor()
			resultsTestids = cur.execute('select studenttestinfo.test_id as test_id from studenttestinfo,teachers where studenttestinfo.email = %s and studenttestinfo.uid = %s and studenttestinfo.completed=1 and teachers.test_id = studenttestinfo.test_id and teachers.show_ans = 1 ', (session['email'], session['uid']))
			resultsTestids = cur.fetchall()
			cur.close()
			return render_template('tests_given.html', cresults = resultsTestids)
		else:
			flash('You are not authorized', 'danger')
			return redirect(url_for('student_index'))
	if request.method == "POST":
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT test_type from teachers where test_id = %s',[tidoption])
		callresults = cur.fetchone()
		cur.close()
		if callresults['test_type'] == "objective":
			cur = mysql.connection.cursor()
			results = cur.execute('select distinct(students.test_id) as test_id, students.email as email, subject,topic,neg_marks from students,studenttestinfo,teachers where students.email = %s and teachers.test_type = %s and students.test_id = %s and students.test_id=teachers.test_id and students.test_id=studenttestinfo.test_id and studenttestinfo.completed=1', (email, "objective", tidoption))
			results = cur.fetchall()
			cur.close()
			results1 = []
			studentResults = None
			for a in results:
				results1.append(neg_marks(a['email'],a['test_id'],a['neg_marks']))
				studentResults = zip(results,results1)
			return render_template('obj_result_student.html', tests=studentResults)
		elif callresults['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			studentResults = cur.execute('select SUM(longtest.marks) as marks, longtest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from longtest,teachers,studenttestinfo where longtest.email = %s and longtest.test_id = %s and longtest.test_id=teachers.test_id and studenttestinfo.test_id=teachers.test_id and longtest.email = studenttestinfo.email and studenttestinfo.completed = 1 and teachers.show_ans=1 group by longtest.test_id', (email, tidoption))
			studentResults = cur.fetchall()
			cur.close()
			return render_template('sub_result_student.html', tests=studentResults)
		elif callresults['test_type'] == "practical":
			cur = mysql.connection.cursor()
			studentResults = cur.execute('select SUM(practicaltest.marks) as marks, practicaltest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from practicaltest,teachers,studenttestinfo where practicaltest.email = %s and practicaltest.test_id = %s and practicaltest.test_id=teachers.test_id and studenttestinfo.test_id=teachers.test_id and practicaltest.email = studenttestinfo.email and studenttestinfo.completed = 1 and teachers.show_ans=1 group by practicaltest.test_id', (email, tidoption))
			studentResults = cur.fetchall()
			cur.close()
			return render_template('prac_result_student.html', tests=studentResults)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('student_index'))

@app.route('/<email>/tests-created')
@user_role_professor
def tests_created(email):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute('select * from teachers where email = %s and uid = %s and show_ans = 1', (email,session['uid']))
		results = cur.fetchall()
		return render_template('tests_created.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('professor_index'))

@app.route('/<email>/tests-created/<testid>', methods = ['POST','GET'])
@user_role_professor
def student_results(email, testid):
	if email == session['email']:
		et = examtypecheck(testid)
		if request.method =='GET':
			if et['test_type'] == "objective":
				cur = mysql.connection.cursor()
				results = cur.execute('select users.name as name,users.email as email, studentTestInfo.test_id as test_id from studentTestInfo, users where test_id = %s and completed = 1 and  users.user_type = %s and studentTestInfo.email=users.email ', (testid,'student'))
				results = cur.fetchall()
				cur.close()
				final = []
				names = []
				scores = []
				count = 1
				for user in results:
					score = marks_calc(user['email'], user['test_id'])
					user['srno'] = count
					user['marks'] = score
					final.append([count, user['name'], score])
					names.append(user['name'])
					scores.append(score)
					count+=1
				return render_template('student_results.html', data=final, labels=names, values=scores)
			elif et['test_type'] == "subjective":
				cur = mysql.connection.cursor()
				results = cur.execute('select users.name as name,users.email as email, longtest.test_id as test_id, SUM(longtest.marks) AS marks from longtest, users where longtest.test_id = %s  and  users.user_type = %s and longtest.email=users.email', (testid,'student'))
				results = cur.fetchall()
				cur.close()
				names = []
				scores = []
				for user in results:
					names.append(user['name'])
					scores.append(user['marks'])
				return render_template('student_results_lqa.html', data=results, labels=names, values=scores)
			elif et['test_type'] == "practical":
				cur = mysql.connection.cursor()
				results = cur.execute('select users.name as name,users.email as email, practicaltest.test_id as test_id, SUM(practicaltest.marks) AS marks from practicaltest, users where practicaltest.test_id = %s  and  users.user_type = %s and practicaltest.email=users.email', (testid,'student'))
				results = cur.fetchall()
				cur.close()
				names = []
				scores = []
				for user in results:
					names.append(user['name'])
					scores.append(user['marks'])
				return render_template('student_results_pqa.html', data=results, labels=names, values=scores)

@app.route('/<email>/disptests')
@user_role_professor
def disptests(email):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute('select * from teachers where email = %s and uid = %s', (email,session['uid']))
		results = cur.fetchall()
		return render_template('disptests.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('professor_index'))

@app.route('/<email>/student_test_history')
@user_role_student
def student_test_history(email):
	if email == session['email']:
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT a.test_id, b.subject, b.topic \
			from studenttestinfo a, teachers b where a.test_id = b.test_id and a.email=%s  \
			and a.completed=1', [email])
		results = cur.fetchall()
		return render_template('student_test_history.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('student_index'))

@app.route('/test_generate', methods=["GET", "POST"])
@user_role_professor
def test_generate():
	if request.method == "POST":
		inputText = request.form["itext"]
		testType = request.form["test_type"]
		noOfQues = request.form["noq"]
		if testType == "objective":
			objective_generator = ObjectiveTest(inputText,noOfQues)
			question_list, answer_list = objective_generator.generate_test()
			testgenerate = zip(question_list, answer_list)
			return render_template('generatedtestdata.html', cresults = testgenerate)
		elif testType == "subjective":
			subjective_generator = SubjectiveTest(inputText,noOfQues)
			question_list, answer_list = subjective_generator.generate_test()
			testgenerate = zip(question_list, answer_list)
			return render_template('generatedtestdata.html', cresults = testgenerate)
		else:
			return None

	

if __name__ == '__main__':
    app.run(debug=True, port = 5001)