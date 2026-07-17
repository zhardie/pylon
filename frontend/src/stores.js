import { writable } from "svelte/store";

// Load initial value from localStorage, defaulting to true if not set
const initialDarkMode = typeof localStorage !== 'undefined'
    ? (localStorage.getItem('pylon-dark-mode') !== 'false')
    : true;

export const darkMode = writable(initialDarkMode);
export const onboarded = writable(true);

// Subscribe to store changes to save updates back to localStorage
if (typeof localStorage !== 'undefined') {
    darkMode.subscribe(value => {
        localStorage.setItem('pylon-dark-mode', String(value));
    });
}