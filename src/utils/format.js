//Format errors to be sent to the client
export const formatValidationError = (errors) => {
  // If errors is null or undefined, return a default message
  if(!errors || !errors.issues)
    return 'Validation failed';

  // If errors.issues is an array
  if(Array.isArray(errors.issues))
    return errors.issues.map(issue => issue.message).join(', ');

  // If errors is a single error object
  return JSON.stringify(errors);
};