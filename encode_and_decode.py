
from tkinter import *
import base64

# initialize window
root = Tk()
root.geometry('500x350')
root['background']='#736e6e'
root.resizable(0, 0)

# title of the window
root.title("Message Encode and Decode")

# label

Label(root, text='ENCODE AND DECODE', bg='#736e6e', font='arial 20 bold').pack()

Label(root, text='Powered by ColoAI', bg='#736e6e', font='Courier 10 bold').pack(side=BOTTOM)

# define variables

Text = StringVar()
private_key = StringVar()
mode = StringVar()
Result = StringVar()


#######define function#####

# function to encode

def Encode(key, message):
    enc = []
    for i in range(len(message)):
        key_c = key[i % len(key)]
        enc.append(chr((ord(message[i]) + ord(key_c)) % 256))

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# function to decode

def Decode(key, message):
    dec = []
    message = base64.urlsafe_b64decode(message).decode()
    for i in range(len(message)):
        key_c = key[i % len(key)]
        dec.append(chr((256 + ord(message[i]) - ord(key_c)) % 256))

    return "".join(dec)


# function to set mode

def Mode():
    if mode.get() == 'e':
        Result.set(Encode(private_key.get(), Text.get()))
    elif mode.get() == 'd':
        Result.set(Decode(private_key.get(), Text.get()))
    else:
        Result.set('Invalid Mode. Please please try again')


# Function to exit window

def Exit():
    root.destroy()


# Function to reset
def Reset():
    Text.set("")
    private_key.set("")
    mode.set("")
    Result.set("")


#################### Label and Button #############
#################### Interface #######################

# Message
Label(root, font='arial 12 bold',  bg='#736e6e', text='MESSAGE').place(x=10, y=60)
Entry(root, font='arial 10', textvariable=Text, width=30, bg='#f4f4f4').place(x=190, y=60)

# key
Label(root, font='arial 12 bold', bg='#736e6e', text='KEY').place(x=10, y=100)
Entry(root, font='arial 10', textvariable=private_key, width=30, bg="#f4f4f4").place(x=190, y=100)

# mode
Label(root, font='arial 12 bold',  bg='#736e6e', text="MODE").place(x=10, y=140)
Label(root, font='arial 12 bold', bg='#736e6e', text="( e - Encode, d - Decode )").place(x=270, y=140)
Entry(root, font='arial 10', textvariable=mode, width=10, bg='#f4f4f4').place(x=190, y=140)

# result
Entry(root, font='arial 10 bold', textvariable=Result, width=40, bg='#f4f4f4').place(x=190, y=220)

# result button
Button(root, font='Courier 15 bold', text='RESULT', padx=19, bg='#4d4a4a', command=Mode).place(x=10, y=220)

# reset button
Button(root, font='Courier 15 bold', text='RESET', width=6, command=Reset, bg='#5e5b5b', padx=1 , pady=1).place(x=10, y=310)

# exit button
Button(root, font='Courier 15 bold', text='EXIT', width=6, command=Exit, bg='#5e5b5b', padx=1, pady=1).place(x=410, y=310)
root.mainloop()
