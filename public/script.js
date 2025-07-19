const priceList = {
  "ORYX 46 ft": 500,
  "Majesty 56 ft": 800,
  "Fishing/Speed Boat 31 ft": 349,
  "ORYX 36 ft": 400
};

function calculatePrice() {
  const boat = document.getElementById('boat').value;
  const hours = Number(document.getElementById('hours').value);
  if (boat && hours) {
    const total = priceList[boat] * hours;
    document.getElementById('price').textContent = `Total: AED ${total}`;
  } else {
    document.getElementById('price').textContent = '';
  }
}

document.getElementById('boat').addEventListener('change', calculatePrice);
document.getElementById('hours').addEventListener('input', calculatePrice);
