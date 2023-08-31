import pickle
import os
import random
import get_fake_name
import get_fake_birthday
import generate_real_password

#fake_unique_id = random.choice(range(100000000, 999999999))

if os.path.exists("fake_americans.pickle"):
    with open ("fake_americans.pickle", "rb") as f:
        all_fake_americans = pickle.load(f)
else:
    all_fake_americans = {}
    
fake_unique_id = random.choice(range(100000000, 999999999))
if fake_unique_id not in all_fake_americans:
    pass
else:
    while fake_unique_id not in all_fake_americans:
        fake_unique_id = random.choice(range(100000000, 999999999))

new_fake_american = {'fake_unique_id': fake_unique_id, 'fake_name': get_fake_name.generate_names(), 'fake_birthday': get_fake_birthday.generate_fake_birthday(), 'fake_password': generate_real_password.main()}

all_fake_americans[fake_unique_id] = new_fake_american

with open('fake_americans.pickle', 'wb') as f:
    pickle.dump(all_fake_americans, f)