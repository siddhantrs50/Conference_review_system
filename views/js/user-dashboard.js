document.addEventListener('DOMContentLoaded', () => {
    const papersList = document.getElementById('papersList');
    const newPaperForm = document.getElementById('newPaperForm');
    const submissionMessage = document.getElementById('submissionMessage');
  
    const userToken = localStorage.getItem('userToken');
  
    if (!userToken) {
      window.location.href = 'index.html'; // Redirect if not logged in
      return;
    }
  
    // Function to fetch and display user's submitted papers
    async function fetchPapers() {
      try {
        const response = await fetch('http://localhost:3000/user-papers', {
          headers: {
            'Authorization': `Bearer ${userToken}`
          }
        });
  
        const papers = await response.json();
  
        if (response.ok) {
          papersList.innerHTML = ''; // Clear existing list
          if (papers.length === 0) {
            papersList.innerHTML = '<li class="text-white">No papers submitted yet.</li>';
          } else {
            papers.forEach(paper => {
              const li = document.createElement('li');
              li.className = "p-4 bg-white bg-opacity-20 rounded-md";
              li.innerHTML = `<h3 class="text-lg font-semibold">${paper.title}</h3>
                              <p class="text-sm">${paper.abstract}</p>`;
              papersList.appendChild(li);
            });
          }
        } else {
          papersList.innerHTML = `<li class="text-red-400">${papers.error || 'Failed to load papers.'}</li>`;
        }
  
      } catch (error) {
        console.error(error);
        papersList.innerHTML = '<li class="text-red-400">Error loading papers.</li>';
      }
    }
  
    // Handle new paper submission
    newPaperForm.addEventListener('submit', async (e) => {
      e.preventDefault();
  
      const title = document.getElementById('paperTitle').value;
      const abstract = document.getElementById('paperAbstract').value;
  
      try {
        const response = await fetch('http://localhost:3000/submit-paper', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${userToken}`
          },
          body: JSON.stringify({ title, abstract })
        });
  
        const result = await response.json();
  
        if (response.ok) {
          submissionMessage.textContent = 'Paper submitted successfully!';
          submissionMessage.className = 'text-green-400';
          newPaperForm.reset();
          fetchPapers(); // Reload papers list
        } else {
          submissionMessage.textContent = result.error || 'Submission failed.';
          submissionMessage.className = 'text-red-400';
        }
  
      } catch (error) {
        console.error(error);
        submissionMessage.textContent = 'Something went wrong!';
        submissionMessage.className = 'text-red-400';
      }
    });
  
    // Initial fetch on page load
    fetchPapers();
  });
  