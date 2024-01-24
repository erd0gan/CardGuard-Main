const input = document.querySelector("keyInput");
const inputIcon = document.querySelector(".input__icon");

inputIcon.addEventListener("click", (e) => {
    e.preventDefault();

    inputIcon.setAttribute(
        'src', 
        input.getAttribute('type') === 'password' ?
        'eye-off.svg'
          :
        'eye.svg'
    );

    input.setAttribute(
        'type', 
        input.getAttribute('type') === 'password' ? 
        'text'
          :
        'password'
    );
});